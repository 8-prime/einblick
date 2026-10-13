use crate::{storage::Database, *};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};
use std::collections::BTreeMap;

impl Database {
    pub async fn events_for_source(
        &self,
        ip: std::net::IpAddr,
        limit: u32,
        before: i64,
    ) -> Result<Vec<Event>> {
        self.read(move |c| {
            let mut s=c.prepare("SELECT id,at,kind,detail FROM events WHERE id<? AND json_extract(detail,'$.ip')=? ORDER BY id DESC LIMIT ?")?;
            let mut rows=s.query(params![before,ip.to_string(),limit.min(200)])?;
            let mut out=vec![];let mut bytes=0;
            while let Some(row)=rows.next()? {
                let data:String=row.get(3)?;bytes+=data.len();if bytes>4*1024*1024 {break;}
                out.push(Event{id:row.get(0)?,at:row.get(1)?,kind:row.get(2)?,detail:serde_json::from_str(&data)?});
            }
            Ok(out)
        }).await
    }
    pub async fn detail_checkpoint(
        &self,
        batch: DetailBatch,
        retention: config::Retention,
        cap: usize,
    ) -> Result<()> {
        self.call(move |c| {
            let t = c.transaction()?;
            let new_run: bool = !t.query_row("SELECT EXISTS(SELECT 1 FROM traffic_batches WHERE run=?)",[&batch.run],|r|r.get::<_,bool>(0))?;
            let previous_end: Option<i64> = t.query_row("SELECT max(last_seen) FROM traffic_coverage WHERE resolution='minute'",[],|r|r.get(0))?;
            let restart_gap = previous_end.filter(|&end|new_run && end < batch.from-1);
            let gap_from = batch.gap_from.into_iter().chain(restart_gap).min();
            if t.execute("INSERT OR IGNORE INTO traffic_batches VALUES(?,?,?)", params![batch.run,i64::try_from(batch.sequence)?,batch.to])? == 0 { return Ok(()); }
            t.execute("INSERT OR IGNORE INTO settings VALUES('traffic_started',?)", [batch.from.to_string()])?;
            let mut application_collected=false;
            for (resolution, span) in [("minute",60),("hour",3600)] {
                let at = batch.from / span * span;
                for row in &batch.rows {
                    let port = row.port.map_or(-1, i32::from);
                    let mut merged = row.clone();
                    let old: Option<(String,bool)> = t.prepare_cached("SELECT source_ports,truncated FROM traffic WHERE resolution=? AND at=? AND source=? AND destination=? AND interface=? AND protocol=? AND port=?")?.query_row(
                        params![resolution,at,row.source.to_string(),row.destination.to_string(),row.interface,row.protocol,port], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
                    let previously_collected = old.is_some();
                    if let Some((ports,truncated)) = old {
                        let mut previous = row.clone(); previous.source_ports = serde_json::from_str(&ports)?; previous.source_ports_truncated = truncated;
                        merged.merge(&previous); // only the bounded sample is taken from this merge
                    }
                    t.prepare_cached("INSERT INTO traffic VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(resolution,at,source,destination,interface,protocol,port) DO UPDATE SET
                        packets=packets+excluded.packets,bytes=bytes+excluded.bytes,passed=passed+excluded.passed,dropped=dropped+excluded.dropped,
                        syns=syns+excluded.syns,syn_acks=syn_acks+excluded.syn_acks,resets=resets+excluded.resets,
                        first_seen=min(first_seen,excluded.first_seen),last_seen=max(last_seen,excluded.last_seen),source_ports=excluded.source_ports,truncated=excluded.truncated")?.execute(
                        params![resolution,at,row.source.to_string(),row.destination.to_string(),row.interface,row.protocol,port,
                            i64::try_from(row.counts.packets)?,i64::try_from(row.counts.bytes)?,i64::try_from(row.counts.passed)?,i64::try_from(row.counts.dropped)?,i64::try_from(row.counts.syns)?,i64::try_from(row.counts.syn_acks)?,i64::try_from(row.counts.resets)?,
                            row.first_seen,row.last_seen,serde_json::to_string(&merged.source_ports)?,merged.source_ports_truncated])?;
                    let old: Option<String> = t.prepare_cached("SELECT data FROM traffic_applications WHERE resolution=? AND at=? AND source=? AND destination=? AND interface=? AND protocol=? AND port=?")?.query_row(
                        params![resolution,at,row.source.to_string(),row.destination.to_string(),row.interface,row.protocol,port], |r|r.get(0)).optional()?;
                    let mut attribution=match old {
                        Some(old)=>serde_json::from_str::<ApplicationAttribution>(&old)?,
                        None if previously_collected=>ApplicationAttribution::default(),
                        None=>ApplicationAttribution { applications:vec![],reasons:vec![] },
                    };
                    attribution.merge(&row.application_attribution);
                    t.prepare_cached("INSERT INTO traffic_applications VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(resolution,at,source,destination,interface,protocol,port) DO UPDATE SET data=excluded.data")?.execute(
                        params![resolution,at,row.source.to_string(),row.destination.to_string(),row.interface,row.protocol,port,serde_json::to_string(&attribution)?])?;
                    if !attribution.applications.is_empty() || attribution.reasons.iter().any(|r|!matches!(r,ApplicationReason::NotCollected|ApplicationReason::Disabled)) {
                        application_collected=true;
                    }
                }
                t.execute("INSERT INTO traffic_coverage VALUES(?,?,?,?,?,?) ON CONFLICT(resolution,at) DO UPDATE SET complete=complete AND excluded.complete,
                    omitted=omitted+excluded.omitted,first_seen=min(first_seen,excluded.first_seen),last_seen=max(last_seen,excluded.last_seen)",
                    params![resolution,at,batch.complete,i64::try_from(batch.omitted)?,batch.from,batch.to])?;
                if let Some(start) = gap_from {
                    // Coverage only, never fabricated zero-traffic rows. Bound even
                    // a long downtime by the API's maximum queryable history.
                    let days = if resolution=="minute" {retention.minute_days}else{retention.hourly_days};
                    let start = start.max(batch.to-days.min(90)*86400).max(0);
                    for gap_at in (start/span*span..=at).step_by(span as usize) {
                        t.execute("INSERT INTO traffic_coverage VALUES(?,?,0,0,?,?) ON CONFLICT(resolution,at) DO UPDATE SET complete=0,
                            first_seen=min(first_seen,excluded.first_seen),last_seen=max(last_seen,excluded.last_seen)",
                            params![resolution,gap_at,start.max(gap_at),batch.from.min(gap_at+span)])?;
                    }
                }
            }
            if application_collected { t.execute("INSERT OR IGNORE INTO settings VALUES('application_attribution_started',?)",[batch.from.to_string()])?; }
            for (resolution,days) in [("minute",retention.minute_days),("hour",retention.hourly_days)] {
                let cutoff = batch.to - days*86400;
                t.execute("DELETE FROM traffic WHERE resolution=? AND at<?", params![resolution,cutoff])?;
                t.execute("DELETE FROM traffic_coverage WHERE resolution=? AND at<?", params![resolution,cutoff])?;
            }
            // Retain batch identities as long as their hourly data to make retries idempotent.
            t.execute("DELETE FROM traffic_batches WHERE at<?", [batch.to-retention.hourly_days*86400])?;
            let mut count: usize = t.query_row("SELECT count(*) FROM traffic", [], |r|Ok(r.get::<_,i64>(0)? as usize))?;
            while count > cap {
                let (resolution,at,n): (String,i64,usize) = t.query_row("SELECT resolution,at,count(*) FROM traffic GROUP BY resolution,at ORDER BY at,resolution LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get::<_,i64>(2)? as usize)))?;
                t.execute("DELETE FROM traffic WHERE resolution=? AND at=?",params![resolution,at])?;
                t.execute("DELETE FROM traffic_coverage WHERE resolution=? AND at<=?",params![resolution,at])?;
                t.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=max(CAST(value AS INTEGER),CAST(excluded.value AS INTEGER))",
                    params![format!("traffic_{resolution}_floor"), (at + if resolution=="minute"{60}else{3600}).to_string()])?;
                count -= n;
            }
            t.commit()?; Ok(())
        }).await
    }

    pub async fn source_traffic(&self, q: TrafficQuery, live: LiveTraffic) -> Result<TrafficPage> {
        ensure!(
            q.resolution == "minute" || q.resolution == "hour",
            "resolution must be minute or hour"
        );
        ensure!(
            q.from >= 0 && q.to >= q.from && q.to - q.from <= 90 * 86400,
            "invalid range; maximum 90 days"
        );
        ensure!(
            (1..=500).contains(&q.limit),
            "limit must be between 1 and 500"
        );
        self.read(move |c| {
            // The aggregate query and committed-batch check share a SQLite snapshot.
            // A flush racing this read therefore cannot double-count live data.
            let t = c.transaction()?;
            let span = if q.resolution=="minute" {60} else {3600};
            let from = q.from/span*span;
            let to = q.to/span*span;
            let cursor = q.cursor.clone().unwrap_or_default();
            let mut s = t.prepare("SELECT destination,interface,protocol,port,sum(packets),sum(bytes),sum(passed),sum(dropped),sum(syns),sum(syn_acks),sum(resets),min(first_seen),max(last_seen),min(source_ports),max(truncated) OR count(DISTINCT source_ports)>1
                FROM traffic WHERE source=? AND resolution=? AND at>=? AND at<=? AND (? IS NULL OR protocol=?) AND (? IS NULL OR port=?)
                AND (destination,interface,protocol,port)>(?,?,?,?) GROUP BY destination,interface,protocol,port ORDER BY destination,interface,protocol,port LIMIT ?")?;
            let mut rows = s.query(params![q.ip.to_string(),q.resolution,from,to,q.protocol,q.protocol,q.port,q.port,cursor.0,cursor.1,cursor.2,cursor.3,(q.limit+1) as i64])?;
            let mut found = BTreeMap::new();
            while let Some(r) = rows.next()? {
                let port: i32 = r.get(3)?;
                let record = TrafficRecord {source:q.ip,destination:r.get::<_,String>(0)?.parse()?,interface:r.get(1)?,protocol:r.get(2)?,port:if port<0{None}else{Some(port as u16)},
                    counts:TrafficCounts{packets:r.get::<_,i64>(4)? as u64,bytes:r.get::<_,i64>(5)? as u64,passed:r.get::<_,i64>(6)? as u64,dropped:r.get::<_,i64>(7)? as u64,syns:r.get::<_,i64>(8)? as u64,syn_acks:r.get::<_,i64>(9)? as u64,resets:r.get::<_,i64>(10)? as u64},
                    first_seen:r.get(11)?,last_seen:r.get(12)?,source_ports:serde_json::from_str(&r.get::<_,String>(13)?)?,source_ports_truncated:r.get(14)?,application_attribution:ApplicationAttribution{applications:vec![],reasons:vec![]}};
                found.insert(record.cursor(),record);
            }
            // Read only selected associations, streaming and bounding enrichment work.
            // LEFT JOIN retains explicit "not collected" evidence for pre-v3 history.
            let mut attribution_bytes = 0;
            let mut attribution_rows = 0;
            let mut app_statement = t.prepare("SELECT a.data FROM traffic t LEFT JOIN traffic_applications a USING(resolution,at,source,destination,interface,protocol,port)
                WHERE t.source=? AND t.resolution=? AND t.at>=? AND t.at<=? AND t.destination=? AND t.interface=? AND t.protocol=? AND t.port=? ORDER BY t.at LIMIT 10001")?;
            for record in found.values_mut() {
                if attribution_bytes >= 16*1024*1024 || attribution_rows >= 10000 {
                    record.application_attribution.reason(ApplicationReason::QueryLimit);
                    continue;
                }
                let mut apps = app_statement.query(params![q.ip.to_string(),q.resolution,from,to,record.destination.to_string(),record.interface,record.protocol,record.port.map_or(-1,i32::from)])?;
                while let Some(r) = apps.next()? {
                    let data: Option<String> = r.get(0)?;
                    attribution_rows += 1;
                    attribution_bytes += data.as_ref().map_or(0,|s|s.len());
                    if attribution_bytes > 16*1024*1024 || attribution_rows > 10000 {
                        record.application_attribution.reason(ApplicationReason::QueryLimit);
                        break;
                    }
                    let attribution = data.map(|s|serde_json::from_str::<ApplicationAttribution>(&s)).transpose()?.unwrap_or_default();
                    record.application_attribution.merge(&attribution);
                }
            }
            let (available_from,available_to,n,healthy,omitted):(Option<i64>,Option<i64>,usize,bool,u64) = t.query_row(
                "SELECT min(at),max(at),count(*),coalesce(min(complete),0),coalesce(sum(omitted),0) FROM traffic_coverage WHERE resolution=? AND at>=? AND at<=?",
                params![q.resolution,from,to],|r|Ok((r.get(0)?,r.get(1)?,r.get::<_,i64>(2)? as usize,r.get(3)?,r.get::<_,i64>(4)? as u64)))?;
            let retained_from: Option<i64> = t.query_row("SELECT min(at) FROM traffic_coverage WHERE resolution=?",[&q.resolution],|r|r.get(0))?;
            let stored_start: Option<i64> = t.query_row("SELECT CAST(value AS INTEGER) FROM settings WHERE key='traffic_started'",[],|r|r.get(0)).optional()?;
            let capture_started=stored_start.or_else(||live.batches.iter().map(|b|b.from).min());
            let mut attribution_started: Option<i64> = t.query_row("SELECT CAST(value AS INTEGER) FROM settings WHERE key='application_attribution_started'",[],|r|r.get(0)).optional()?;
            let floor: Option<i64> = t.query_row("SELECT CAST(value AS INTEGER) FROM settings WHERE key=?",[format!("traffic_{}_floor",q.resolution)],|r|r.get(0)).optional()?;
            let stored_rows = t.query_row("SELECT count(*) FROM traffic",[],|r|Ok(r.get::<_,i64>(0)? as usize))?;
            let mut complete = healthy;
            let mut omitted = omitted;
            let mut live_buckets = std::collections::BTreeSet::new();
            let mut has_gap = false;
            let previous_end: Option<i64> = t.query_row("SELECT max(last_seen) FROM traffic_coverage WHERE resolution='minute'",[],|r|r.get(0))?;
            for batch in live.batches {
                let at = batch.from/span*span;
                let committed: bool = t.query_row("SELECT EXISTS(SELECT 1 FROM traffic_batches WHERE run=? AND sequence=?)",params![batch.run,i64::try_from(batch.sequence)?],|r|r.get(0))?;
                if committed {continue;}
                let known_run: bool = t.query_row("SELECT EXISTS(SELECT 1 FROM traffic_batches WHERE run=?)",[&batch.run],|r|r.get(0))?;
                let restart_gap = previous_end.filter(|&end|!known_run && end < batch.from-1);
                if batch.gap_from.into_iter().chain(restart_gap).min().is_some_and(|start|start<=q.to && batch.from>=q.from) {has_gap=true;}
                if at<from || at>to {continue;}
                live_buckets.insert(at);
                if n==0 && live_buckets.len()==1 {complete=true;}
                complete &= batch.complete;
                omitted += batch.omitted;
                for record in batch.rows.into_iter().filter(|r|r.source==q.ip && q.protocol.is_none_or(|p|p==r.protocol) && q.port.is_none_or(|p|Some(p)==r.port) && r.cursor()>cursor) {
                    if !record.application_attribution.applications.is_empty() || record.application_attribution.reasons.iter().any(|r|!matches!(r,ApplicationReason::Disabled|ApplicationReason::NotCollected)) {
                        attribution_started = Some(attribution_started.unwrap_or(batch.from).min(batch.from));
                    }
                    found.entry(record.cursor()).and_modify(|old:&mut TrafficRecord|old.merge(&record)).or_insert(record);
                }
            }
            complete &= !has_gap;
            let mut warnings = vec![];
            let expected_from = from.max(capture_started.unwrap_or(q.to)/span*span);
            if capture_started.is_none_or(|start|q.from<start) {warnings.push("IP detail was not collected before this deployment.".into());complete=false;}
            if floor.is_some_and(|f|expected_from<f) || retained_from.is_some_and(|f|expected_from<f) {warnings.push("Older detail in this range has expired or reached the storage limit.".into());complete=false;}
            // Check bucket identities, not a sum of DB and live counts (which overlap).
            let existing: Vec<i64> = t.prepare("SELECT at FROM traffic_coverage WHERE resolution=? AND at>=? AND at<=?")?
                .query_map(params![q.resolution,expected_from,to],|r|r.get(0))?.collect::<rusqlite::Result<_>>()?;
            let mut coverage: std::collections::BTreeSet<i64> = existing.into_iter().collect(); coverage.extend(live_buckets);
            if coverage.len() < ((to-expected_from)/span+1).max(0) as usize {warnings.push("Some collection intervals are unavailable.".into());complete=false;}
            if !complete && warnings.is_empty() {warnings.push("Traffic detail is incomplete for part of this range.".into());}
            if omitted>0 {warnings.push(format!("{omitted} packet-detail records could not be retained in this range."));}
            let has_more = found.len()>q.limit;
            let mut out:Vec<_> = found.into_values().take(q.limit+1).collect();
            out.truncate(q.limit);
            let mut response_bytes=0;
            let mut keep=0;
            for row in &out {
                response_bytes+=serde_json::to_vec(row)?.len();
                if response_bytes>4*1024*1024-16384 {break;}
                keep+=1;
            }
            let response_limited=keep<out.len();out.truncate(keep);
            let next_cursor = if has_more || response_limited {out.last().map(|r|serde_json::to_string(&r.cursor())).transpose()?}else{None};
            if response_limited {warnings.push("Response size limit reached; load the next page.".into());}
            Ok(TrafficPage{ip_info:None,rows:out,next_cursor,capture_started,attribution_started,available_from:retained_from.or(available_from),available_to:available_to.map(|at|at+span),complete,omitted,stored_rows,warnings})
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(source: &str, port: Option<u16>) -> TrafficRecord {
        TrafficRecord {
            source: source.parse().unwrap(),
            destination: "192.0.2.1".parse().unwrap(),
            interface: "eth0".into(),
            protocol: 6,
            port,
            counts: TrafficCounts {
                packets: 3,
                bytes: 180,
                passed: 2,
                dropped: 1,
                syns: 1,
                syn_acks: 1,
                resets: 1,
            },
            first_seen: 120,
            last_seen: 129,
            source_ports: vec![51000],
            source_ports_truncated: false,
            application_attribution: ApplicationAttribution::default(),
        }
    }
    fn batch(sequence: u64, rows: Vec<TrafficRecord>) -> DetailBatch {
        DetailBatch {
            run: "test-run".into(),
            sequence,
            from: 120,
            to: 130,
            rows,
            complete: true,
            omitted: 0,
            gap_from: None,
        }
    }
    fn query(ip: &str) -> TrafficQuery {
        TrafficQuery {
            ip: ip.parse().unwrap(),
            resolution: "minute".into(),
            from: 120,
            to: 130,
            protocol: None,
            port: None,
            cursor: None,
            limit: 100,
        }
    }
    fn attributed(name: &str, pid: u32) -> TrafficRecord {
        let mut row = record("192.0.2.10", Some(443));
        row.application_attribution = ApplicationAttribution {
            applications: vec![],
            reasons: vec![],
        };
        row.application_attribution.add(ApplicationEvidence {
            id: format!("process:{pid}:123"),
            name: name.into(),
            method: ApplicationMethod::SocketOwner,
            pid: Some(pid),
            process_start: Some(123),
            executable: None,
            service: None,
            container_id: None,
            observed_from: 120,
            observed_to: 129,
        });
        row
    }

    #[tokio::test]
    async fn application_history_preserves_port_reassignment_and_retry_identity() {
        let db = Database::open(":memory:").unwrap();
        let first = batch(1, vec![attributed("nginx", 10)]);
        db.detail_checkpoint(first.clone(), config::Retention::default(), 1000)
            .await
            .unwrap();
        db.detail_checkpoint(first.clone(), config::Retention::default(), 1000)
            .await
            .unwrap();
        let second = batch(2, vec![attributed("caddy", 11)]);
        let live = LiveTraffic {
            batches: vec![first, second.clone()],
        };
        let before = db.source_traffic(query("192.0.2.10"), live).await.unwrap();
        assert_eq!(before.rows[0].counts.packets, 6);
        assert_eq!(before.rows[0].application_attribution.applications.len(), 2);
        db.detail_checkpoint(second, config::Retention::default(), 1000)
            .await
            .unwrap();
        let after = db
            .source_traffic(query("192.0.2.10"), LiveTraffic::default())
            .await
            .unwrap();
        assert_eq!(
            after.rows[0].application_attribution,
            before.rows[0].application_attribution
        );
        assert_eq!(after.rows[0].counts.packets, 6);
        assert_eq!(after.attribution_started, Some(120));
        let mut hour = query("192.0.2.10");
        hour.resolution = "hour".into();
        let rolled = db
            .source_traffic(hour, LiveTraffic::default())
            .await
            .unwrap();
        assert_eq!(rolled.rows[0].application_attribution.applications.len(), 2);
        assert_eq!(rolled.rows[0].counts.packets, 6);
    }

    #[tokio::test]
    async fn unknown_history_does_not_suppress_later_attribution() {
        for legacy in [false, true] {
            for later_from in [130, 180] {
                let db = Database::open(":memory:").unwrap();
                db.detail_checkpoint(
                    batch(1, vec![record("192.0.2.10", Some(443))]),
                    config::Retention::default(),
                    1000,
                )
                .await
                .unwrap();
                if legacy {
                    // Migrated history has traffic without an attribution sidecar.
                    db.call(|c| {
                        c.execute("DELETE FROM traffic_applications", [])?;
                        Ok(())
                    })
                    .await
                    .unwrap();
                }
                let original = db
                    .source_traffic(query("192.0.2.10"), LiveTraffic::default())
                    .await
                    .unwrap();
                assert_eq!(original.rows[0].counts.packets, 3);
                assert_eq!(
                    original.rows[0].application_attribution,
                    ApplicationAttribution::default()
                );

                let mut row = attributed("nginx", 10);
                row.first_seen = later_from;
                row.last_seen = later_from + 9;
                row.application_attribution.applications[0].observed_from = later_from;
                row.application_attribution.applications[0].observed_to = later_from + 9;
                let expected_evidence = row.application_attribution.applications.clone();
                let mut later = batch(2, vec![row]);
                later.from = later_from;
                later.to = later_from + 10;
                let mut q = query("192.0.2.10");
                q.to = later.to;
                let before = db
                    .source_traffic(
                        q.clone(),
                        LiveTraffic {
                            batches: vec![later.clone()],
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(before.rows.len(), 1);
                assert_eq!(before.rows[0].counts.packets, 6);
                assert_eq!(
                    (before.rows[0].first_seen, before.rows[0].last_seen),
                    (120, later_from + 9)
                );
                assert_eq!(
                    before.rows[0].application_attribution.applications,
                    expected_evidence
                );
                assert_eq!(
                    before.rows[0].application_attribution.reasons,
                    vec![ApplicationReason::NotCollected]
                );
                db.detail_checkpoint(later, config::Retention::default(), 1000)
                    .await
                    .unwrap();
                for resolution in ["minute", "hour"] {
                    q.resolution = resolution.into();
                    let after = db
                        .source_traffic(q.clone(), LiveTraffic::default())
                        .await
                        .unwrap();
                    assert_eq!(after.rows[0].counts.packets, 6);
                    assert_eq!(
                        after.rows[0].application_attribution,
                        before.rows[0].application_attribution
                    );
                }
                if later_from == 180 {
                    // Selecting only the later minute has no earlier unknown reason.
                    q.resolution = "minute".into();
                    q.from = later_from;
                    let recent = db.source_traffic(q, LiveTraffic::default()).await.unwrap();
                    assert_eq!(recent.rows[0].counts.packets, 3);
                    assert_eq!(
                        recent.rows[0].application_attribution.applications,
                        expected_evidence
                    );
                    assert!(recent.rows[0].application_attribution.reasons.is_empty());
                }
            }
        }
    }

    #[tokio::test]
    async fn saturated_application_sets_are_consistent_before_and_after_commit() {
        let db = Database::open(":memory:").unwrap();
        let mut row = attributed("worker-10", 10);
        for pid in 11..18 {
            row.application_attribution.add(
                attributed(&format!("worker-{pid}"), pid)
                    .application_attribution
                    .applications
                    .remove(0),
            );
        }
        db.detail_checkpoint(batch(1, vec![row]), config::Retention::default(), 1000)
            .await
            .unwrap();
        let second = batch(2, vec![attributed("new-worker", 99)]);
        let before = db
            .source_traffic(
                query("192.0.2.10"),
                LiveTraffic {
                    batches: vec![second.clone()],
                },
            )
            .await
            .unwrap();
        db.detail_checkpoint(second, config::Retention::default(), 1000)
            .await
            .unwrap();
        let after = db
            .source_traffic(query("192.0.2.10"), LiveTraffic::default())
            .await
            .unwrap();
        assert_eq!(
            before.rows[0].application_attribution,
            after.rows[0].application_attribution
        );
        assert_eq!(after.rows[0].counts.packets, 6);
        assert!(
            after.rows[0]
                .application_attribution
                .reasons
                .contains(&ApplicationReason::Truncated)
        );
    }

    #[tokio::test]
    async fn legacy_evidence_stays_unknown_and_sidecars_follow_bucket_pruning() {
        let db = Database::open(":memory:").unwrap();
        db.detail_checkpoint(
            batch(1, vec![record("192.0.2.10", Some(443))]),
            config::Retention::default(),
            1000,
        )
        .await
        .unwrap();
        // Simulate a migrated v2 traffic bucket with no attribution sidecar.
        db.call(|c| {
            c.execute("DELETE FROM traffic_applications", [])?;
            Ok(())
        })
        .await
        .unwrap();
        db.detail_checkpoint(
            batch(2, vec![attributed("nginx", 10)]),
            config::Retention::default(),
            1000,
        )
        .await
        .unwrap();
        let page = db
            .source_traffic(query("192.0.2.10"), LiveTraffic::default())
            .await
            .unwrap();
        assert!(
            page.rows[0]
                .application_attribution
                .reasons
                .contains(&ApplicationReason::NotCollected)
        );
        assert_eq!(page.rows[0].counts.packets, 6);
        let mut later = batch(3, vec![attributed("caddy", 11)]);
        later.from = 180;
        later.to = 190;
        db.detail_checkpoint(later, config::Retention::default(), 1)
            .await
            .unwrap();
        let orphan_count=db.read(|c|Ok(c.query_row("SELECT count(*) FROM traffic_applications a LEFT JOIN traffic t USING(resolution,at,source,destination,interface,protocol,port) WHERE t.source IS NULL",[],|r|r.get::<_,i64>(0))?)).await.unwrap();
        assert_eq!(orphan_count, 0);
    }

    #[tokio::test]
    async fn version_two_upgrade_backs_up_and_retains_unknown_application_history() {
        let path = std::env::temp_dir().join(format!(
            "einblick-application-migration-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let name = path.to_str().unwrap();
        let old = Database::open(name).unwrap();
        old.detail_checkpoint(
            batch(1, vec![record("192.0.2.10", Some(443))]),
            config::Retention::default(),
            1000,
        )
        .await
        .unwrap();
        old.call(|c| { c.execute_batch("DROP TABLE traffic_applications;DROP INDEX traffic_application_lookup;PRAGMA user_version=2;")?;Ok(()) }).await.unwrap();
        drop(old);
        let upgraded = Database::open(name).unwrap();
        let page = upgraded
            .source_traffic(query("192.0.2.10"), LiveTraffic::default())
            .await
            .unwrap();
        assert_eq!(page.rows[0].counts.packets, 3);
        assert_eq!(
            page.rows[0].application_attribution,
            ApplicationAttribution::default()
        );
        assert_eq!(page.attribution_started, None);
        let backup = rusqlite::Connection::open(format!("{name}.schema-v2-backup")).unwrap();
        assert_eq!(
            backup
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            backup
                .query_row(
                    "SELECT sum(packets) FROM traffic WHERE resolution='minute'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            3
        );
        drop(backup);
        drop(upgraded);
        for suffix in ["", "-wal", "-shm", ".schema-v2-backup"] {
            let _ = std::fs::remove_file(format!("{name}{suffix}"));
        }
    }

    #[tokio::test]
    async fn historical_enrichment_limit_does_not_truncate_traffic_counts() {
        let db = Database::open(":memory:").unwrap();
        db.detail_checkpoint(
            batch(1, vec![attributed("nginx", 10)]),
            config::Retention::default(),
            100000,
        )
        .await
        .unwrap();
        db.call(|c| {
            c.execute_batch("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<10000)
                INSERT INTO traffic SELECT resolution,at+i*60,source,destination,interface,protocol,port,packets,bytes,passed,dropped,syns,syn_acks,resets,first_seen+i*60,last_seen+i*60,source_ports,truncated
                FROM traffic,n WHERE resolution='minute' AND at=120;")?;
            Ok(())
        }).await.unwrap();
        let mut q = query("192.0.2.10");
        q.to = 600130;
        let page = db.source_traffic(q, LiveTraffic::default()).await.unwrap();
        assert_eq!(page.rows[0].counts.packets, 30003);
        assert!(
            page.rows[0]
                .application_attribution
                .reasons
                .contains(&ApplicationReason::QueryLimit)
        );
        assert!(
            page.rows[0]
                .application_attribution
                .reasons
                .contains(&ApplicationReason::NotCollected)
        );
    }
    #[tokio::test]
    async fn associations_roll_up_idempotently_and_live_flush_does_not_duplicate() {
        let db = Database::open(":memory:").unwrap();
        let b = batch(
            1,
            vec![
                record("192.0.2.10", Some(443)),
                record("192.0.2.11", Some(443)),
            ],
        );
        db.detail_checkpoint(b.clone(), config::Retention::default(), 1000)
            .await
            .unwrap();
        db.detail_checkpoint(b.clone(), config::Retention::default(), 1000)
            .await
            .unwrap();
        let live = LiveTraffic {
            batches: vec![b.clone(), batch(2, vec![record("192.0.2.10", Some(443))])],
        };
        let page = db.source_traffic(query("192.0.2.10"), live).await.unwrap();
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].counts.packets, 6);
        assert_eq!(page.rows[0].counts.dropped, 2);
        let mut q = query("192.0.2.10");
        q.resolution = "hour".into();
        assert_eq!(
            db.source_traffic(q, LiveTraffic::default())
                .await
                .unwrap()
                .rows[0]
                .counts
                .packets,
            3
        );
        assert_eq!(
            db.source_traffic(query("192.0.2.11"), LiveTraffic::default())
                .await
                .unwrap()
                .rows[0]
                .counts
                .packets,
            3
        );
    }
    #[tokio::test]
    async fn pagination_filters_unknown_ports_and_low_volume_sources() {
        let db = Database::open(":memory:").unwrap();
        db.detail_checkpoint(
            batch(
                1,
                vec![
                    record("2001:db8::10", None),
                    record("2001:db8::10", Some(0)),
                    record("2001:db8::10", Some(22)),
                    record("2001:db8::10", Some(443)),
                ],
            ),
            config::Retention::default(),
            1000,
        )
        .await
        .unwrap();
        let mut q = query("2001:db8::10");
        q.limit = 2;
        let first = db
            .source_traffic(q.clone(), LiveTraffic::default())
            .await
            .unwrap();
        assert_eq!(first.rows[0].port, None);
        assert_eq!(first.rows[1].port, Some(0));
        q.cursor = Some(serde_json::from_str(first.next_cursor.as_ref().unwrap()).unwrap());
        let next = db.source_traffic(q, LiveTraffic::default()).await.unwrap();
        assert_eq!(next.rows.len(), 2);
        assert_eq!(next.rows[0].port, Some(22));
        assert!(next.next_cursor.is_none());
        let mut q = query("2001:db8::10");
        q.port = Some(443);
        let filtered = db.source_traffic(q, LiveTraffic::default()).await.unwrap();
        assert_eq!(filtered.rows.len(), 1);
        assert_eq!(filtered.rows[0].port, Some(443));
    }
    #[tokio::test]
    async fn capacity_prunes_oldest_buckets_and_reports_coverage() {
        let db = Database::open(":memory:").unwrap();
        db.detail_checkpoint(
            batch(1, vec![record("192.0.2.10", Some(443))]),
            config::Retention::default(),
            1000,
        )
        .await
        .unwrap();
        let mut newer = batch(2, vec![record("192.0.2.10", Some(22))]);
        newer.from = 180;
        newer.to = 190;
        db.detail_checkpoint(newer, config::Retention::default(), 1)
            .await
            .unwrap();
        let mut q = query("192.0.2.10");
        q.to = 190;
        let page = db.source_traffic(q, LiveTraffic::default()).await.unwrap();
        assert!(page.stored_rows <= 1);
        assert!(!page.complete);
        assert!(!page.warnings.is_empty());
    }
    #[tokio::test]
    async fn new_collector_run_merges_partial_minutes_without_double_counting_hours() {
        let db = Database::open(":memory:").unwrap();
        let mut a = batch(1, vec![record("192.0.2.10", Some(443))]);
        db.detail_checkpoint(a.clone(), config::Retention::default(), 1000)
            .await
            .unwrap();
        a.run = "restart".into();
        a.from = 130;
        a.to = 140;
        db.detail_checkpoint(a, config::Retention::default(), 1000)
            .await
            .unwrap();
        for resolution in ["minute", "hour"] {
            let mut q = query("192.0.2.10");
            q.to = 140;
            q.resolution = resolution.into();
            assert_eq!(
                db.source_traffic(q, LiveTraffic::default())
                    .await
                    .unwrap()
                    .rows[0]
                    .counts
                    .packets,
                6
            );
        }
    }
    #[tokio::test]
    async fn gaps_within_an_existing_bucket_are_reported_live_and_after_checkpoint() {
        for restart in [false, true] {
            let db = Database::open(":memory:").unwrap();
            db.detail_checkpoint(batch(1, vec![]), config::Retention::default(), 1000)
                .await
                .unwrap();
            let mut next = batch(2, vec![record("192.0.2.10", Some(443))]);
            next.from = 150;
            next.to = 160;
            if restart {
                next.run = "restart".into();
            } else {
                next.gap_from = Some(130);
                next.omitted = 12;
                next.complete = false;
            }
            let mut q = query("192.0.2.10");
            q.to = 160;
            let live = db
                .source_traffic(
                    q.clone(),
                    LiveTraffic {
                        batches: vec![next.clone()],
                    },
                )
                .await
                .unwrap();
            assert!(!live.complete);
            assert_eq!(live.rows[0].counts.packets, 3);
            db.detail_checkpoint(next, config::Retention::default(), 1000)
                .await
                .unwrap();
            let stored = db.source_traffic(q, LiveTraffic::default()).await.unwrap();
            assert!(!stored.complete);
            assert_eq!(stored.rows[0].counts.packets, 3);
            assert_eq!(stored.omitted, if restart { 0 } else { 12 });
        }
    }
    #[tokio::test]
    #[ignore = "manual full-minute SQLite resource measurement"]
    async fn full_minute_resource_measurement() {
        let path = std::env::temp_dir().join(format!(
            "einblick-detail-benchmark-{}.sqlite",
            std::process::id()
        ));
        let db = Database::open(path.to_str().unwrap()).unwrap();
        let rows = (0..16384)
            .map(|port| {
                let mut row = attributed("web-service", 10);
                row.port = Some(port);
                row
            })
            .collect();
        let started = std::time::Instant::now();
        db.detail_checkpoint(batch(1, rows), config::Retention::default(), 1_000_000)
            .await
            .unwrap();
        let checkpoint = started.elapsed();
        let mut q = query("192.0.2.10");
        q.limit = 500;
        let started = std::time::Instant::now();
        let page = db.source_traffic(q, LiveTraffic::default()).await.unwrap();
        let query_time = started.elapsed();
        assert_eq!(page.stored_rows, 32768);
        assert_eq!(page.rows.len(), 500);
        assert!(page.next_cursor.is_some());
        let response_bytes = serde_json::to_vec(&page).unwrap().len();
        let database_bytes = db
            .read(|c| {
                Ok(
                    c.pragma_query_value(None, "page_count", |r| r.get::<_, i64>(0))?
                        * c.pragma_query_value(None, "page_size", |r| r.get::<_, i64>(0))?,
                )
            })
            .await
            .unwrap();
        let wal = std::fs::metadata(format!("{}-wal", path.display()))
            .unwrap()
            .len();
        println!(
            "16,384 groups: checkpoint {checkpoint:?}, query {query_time:?}, SQLite {database_bytes} bytes, WAL {wal} bytes, response {response_bytes} bytes"
        );
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
