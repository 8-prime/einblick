#![no_std]
#![no_main]
use aya_ebpf::{bindings::xdp_action,helpers::{bpf_ktime_get_ns,bpf_xdp_get_buff_len},macros::{map,xdp},maps::{Array,HashMap,PerCpuArray,PerCpuHashMap,RingBuf,lpm_trie::{LpmTrie,Key}},programs::XdpContext};
use einblick_common::*;

struct XdpPacket {
    start: usize,
    end: usize,
    length: usize,
}
impl PacketRead for XdpPacket {
    #[inline(always)]
    fn packet_len(&self) -> usize {
        self.length
    }
    #[inline(always)]
    fn read_byte(&self, at: usize) -> Option<u8> {
        // The bounded parser reads at most four 2048-byte IPv6 extension headers.
        // Explicitly bound variable offsets for the verifier before pointer math.
        if at > 16384 {
            return None;
        }
        let pointer = self.start + at;
        if pointer + 1 > self.end {
            return None;
        }
        // Only read after comparing the packet pointer directly with data_end.
        Some(unsafe { (pointer as *const u8).read() })
    }
}

#[map] static METRICS:PerCpuArray<u64>=PerCpuArray::with_max_entries(METRICS_LEN,0);
#[map] static SOURCES:PerCpuHashMap<Address,SourceCounters>=PerCpuHashMap::with_max_entries(4096,1);
#[map] static PORTS:PerCpuHashMap<u32,u64>=PerCpuHashMap::with_max_entries(4096,0);
#[map] static EVENTS:RingBuf=RingBuf::with_byte_size(1<<20,0);
#[map] static LIMIT:PerCpuArray<Limiter>=PerCpuArray::with_max_entries(1,0);
// bit 0 = blocking; bit 1 = active bank. Updating this word is the commit.
#[map] static CONTROL:Array<u32>=Array::with_max_entries(1,0);
#[map] static ALLOW4_A:LpmTrie<[u8;4],Deadline>=LpmTrie::with_max_entries(1024,0);
#[map] static ALLOW6_A:LpmTrie<[u8;16],Deadline>=LpmTrie::with_max_entries(1024,0);
#[map] static BLOCK4_A:LpmTrie<[u8;4],Deadline>=LpmTrie::with_max_entries(1024,0);
#[map] static BLOCK6_A:LpmTrie<[u8;16],Deadline>=LpmTrie::with_max_entries(1024,0);
#[map] static BANS_A:HashMap<Address,Deadline>=HashMap::with_max_entries(1024,1);
#[map] static ALLOW4_B:LpmTrie<[u8;4],Deadline>=LpmTrie::with_max_entries(1024,0);
#[map] static ALLOW6_B:LpmTrie<[u8;16],Deadline>=LpmTrie::with_max_entries(1024,0);
#[map] static BLOCK4_B:LpmTrie<[u8;4],Deadline>=LpmTrie::with_max_entries(1024,0);
#[map] static BLOCK6_B:LpmTrie<[u8;16],Deadline>=LpmTrie::with_max_entries(1024,0);
#[map] static BANS_B:HashMap<Address,Deadline>=HashMap::with_max_entries(1024,1);

#[inline(always)] fn count(index:u32,n:u64) { if let Some(p)=METRICS.get_ptr_mut(index) { unsafe { *p+=n; } } }
#[inline(always)] fn active(value:Option<&Deadline>,now:u64)->bool { value.is_some_and(|d|d.expires_ns==0||d.expires_ns>now) }
#[inline(always)] fn blocked(address:&Address,now:u64)->bool {
    let ctl=CONTROL.get(0).copied().unwrap_or(0);
    if ctl&1==0 { return false; }
    let b=ctl&2!=0;
    let k6=Key::new(128,address.bytes);
    let k4=Key::new(32,[address.bytes[0],address.bytes[1],address.bytes[2],address.bytes[3]]);
    let allow=if address.family==4 {if b {ALLOW4_B.get(&k4)}else{ALLOW4_A.get(&k4)}}else{if b {ALLOW6_B.get(&k6)}else{ALLOW6_A.get(&k6)}};
    if active(allow,now) {return false;}
    let ban=unsafe {if b {BANS_B.get(address)}else{BANS_A.get(address)}};
    if active(ban,now) {return true;}
    let block=if address.family==4 {if b {BLOCK4_B.get(&k4)}else{BLOCK4_A.get(&k4)}}else{if b {BLOCK6_B.get(&k6)}else{BLOCK6_A.get(&k6)}};
    active(block,now)
}
#[xdp]
pub fn ingress(ctx:XdpContext)->u32 {
    // Helper 188 returns a scalar length. Subtracting the verifier's packet
    // pointers requires permission to leak pointers and fails with our caps.
    let len=unsafe {bpf_xdp_get_buff_len(ctx.ctx)} as usize;
    count(TOTAL,1);count(BYTES,len as u64);
    let data=XdpPacket{start:ctx.data(),end:ctx.data_end(),length:len};
    let packet=parse_reader(&data);let now=unsafe {bpf_ktime_get_ns()};
    if packet.limited {count(PARSE_LIMIT,1);}
    if packet.has_address {
        if SOURCES.get_ptr_mut(&packet.source).is_none() {
            // NOEXIST avoids resetting another CPU's newly created entry.
            let _=SOURCES.insert(&packet.source,&SourceCounters::default(),1);
        }
        if let Some(p)=SOURCES.get_ptr_mut(&packet.source) { unsafe {
            if (*p).first_seen==0 {(*p).first_seen=now;}
            (*p).last_seen=now;(*p).packets+=1;(*p).bytes+=len as u64;(*p).syns+=packet.syn as u64;
        }}else{count(MAP_FULL,1);}
        let port_key=((packet.protocol as u32)<<16)|packet.port as u32;
        if PORTS.get_ptr_mut(&port_key).is_none() {let _=PORTS.insert(&port_key,&0,1);}
        if let Some(p)=PORTS.get_ptr_mut(&port_key) {unsafe{*p+=1;}}else{count(MAP_FULL,1);}
        if packet.syn {
            if let Some(l)=LIMIT.get_ptr_mut(0) {unsafe {
                let second=now/1_000_000_000;
                if (*l).second!=second {(*l).second=second;(*l).count=0;}
                // Userspace also caps drain size; all skipped evidence is visible.
                if (*l).count<10000 {
                    (*l).count+=1;
                    let event=SynEvent{address:packet.source,port:packet.port,reserved:0,time_ns:now};
                    if EVENTS.output::<SynEvent>(&event,0).is_err() {count(EVENT_LOSS,1);}
                }else{count(EVENT_LOSS,1);}
            }}
        }
        if blocked(&packet.source,now) {count(DROPPED,1);return xdp_action::XDP_DROP;}
    }
    count(PASSED,1);xdp_action::XDP_PASS
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo)->! {loop{}}
#[unsafe(link_section="license")]
#[unsafe(no_mangle)]
static LICENSE:[u8;4]=*b"GPL\0";
