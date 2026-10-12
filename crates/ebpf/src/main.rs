#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
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
        // Keep the pointer calculation, check and load in one opaque block.
        // LLVM can otherwise merge checks for different offsets, then rebuild
        // a pointer whose bounds the verifier no longer knows (notably after
        // IPv6 extension headers). Check pointer + 1 with a fixed offset:
        // checking pointer < data_end alone leaves variable pointers with a
        // zero readable range in the verifier. 256 represents a failed read.
        let value: u64;
        unsafe {
            core::arch::asm!(
                "{value} = 256",
                "{pointer} += {offset}",
                "{pointer} += 1",
                "if {pointer} > {end} goto +1",
                "{value} = *(u8 *)({pointer} - 1)",
                value = out(reg) value,
                pointer = inout(reg) self.start => _,
                offset = in(reg) at,
                end = in(reg) self.end,
                options(nostack, readonly),
            );
        }
        if value < 256 { Some(value as u8) } else { None }
    }
}

#[map] static METRICS:PerCpuArray<u64>=PerCpuArray::with_max_entries(METRICS_LEN,0);
#[map] static SOURCES:PerCpuHashMap<Address,SourceCounters>=PerCpuHashMap::with_max_entries(4096,1);
#[map] static PORTS_A:PerCpuHashMap<u32,u64>=PerCpuHashMap::with_max_entries(4096,0);
#[map] static PORTS_B:PerCpuHashMap<u32,u64>=PerCpuHashMap::with_max_entries(4096,0);
#[map] static TRAFFIC_A:PerCpuHashMap<AssociationKey,AssociationCounters>=PerCpuHashMap::with_max_entries(4096,0);
#[map] static TRAFFIC_B:PerCpuHashMap<AssociationKey,AssociationCounters>=PerCpuHashMap::with_max_entries(4096,0);
#[map] static OBSERVATION_BANK:Array<u32>=Array::with_max_entries(1,0);
#[map] static WRITERS:PerCpuArray<u64>=PerCpuArray::with_max_entries(1,0);
#[map] static DETAIL_LOSS:PerCpuArray<u64>=PerCpuArray::with_max_entries(4,0);
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
#[inline(always)] fn miss(index:u32) {count(MAP_FULL,1);count(index,1);}
#[inline(always)] fn detail_miss(index:u32,bank:u32,offset:u32) {
    miss(index);if let Some(p)=DETAIL_LOSS.get_ptr_mut(bank*2+offset) {unsafe{*p+=1;}}
}
#[inline(always)] unsafe fn writer_add(pointer:*mut u64,delta:u64) {
    // BPF's atomic XADD is supported although Rust's BPF target does not expose
    // AtomicU64.fetch_add. No readonly/nomem options: this is also a compiler fence.
    unsafe {core::arch::asm!("lock *(u64 *)({pointer} + 0) += {delta}",pointer=in(reg)pointer,delta=in(reg)delta,options(nostack));}
}
// Register BEFORE reading the bank selector. After switching it, userspace waits
// for every CPU's writer count to reach zero before touching the old bank.
// Atomic/volatile operations prevent compiler movement across this handshake;
// the supported x86-64 target provides the required hardware ordering.
#[inline(always)] fn record(packet:&Packet,interface:u32,len:u64,now:u64,drop:bool) {
    let Some(w)=WRITERS.get_ptr_mut(0) else {miss(PORT_MISS);miss(ASSOCIATION_MISS);return;};
    unsafe {writer_add(w,1);}
    let bank=OBSERVATION_BANK.get_ptr(0).map(|p|unsafe{core::ptr::read_volatile(p)}).unwrap_or(0);
    let ports=if bank==0 {&PORTS_A}else{&PORTS_B};
    let key=((packet.protocol as u32)<<16)|packet.port as u32;
    if ports.get_ptr_mut(&key).is_none() {let _=ports.insert(&key,&0,1);}
    if let Some(p)=ports.get_ptr_mut(&key) {unsafe{*p+=1;}}else{detail_miss(PORT_MISS,bank,0);}
    let traffic=if bank==0 {&TRAFFIC_A}else{&TRAFFIC_B};
    let key=AssociationKey{source:packet.source,destination:packet.destination,interface,
        protocol:packet.protocol as u32,port:packet.port as u32,parsed:packet.transport_parsed as u32};
    if traffic.get_ptr_mut(&key).is_none() {let _=traffic.insert(&key,&AssociationCounters::default(),1);}
    if let Some(p)=traffic.get_ptr_mut(&key) {unsafe{
        let value=&mut *p;
        value.packets+=1;value.bytes+=len;value.passed+=(!drop) as u64;value.dropped+=drop as u64;
        value.syns+=packet.syn as u64;value.syn_acks+=(packet.tcp_flags&0x12==0x12) as u64;
        value.resets+=(packet.tcp_flags&4!=0) as u64;
        if value.first_seen==0 {value.first_seen=now;}value.last_seen=now;
        if packet.transport_parsed {
            let mut found=false;
            for i in 0..8 {if i<value.source_port_count as usize && value.source_ports[i]==packet.source_port {found=true;}}
            if !found {if value.source_port_count<8 {for i in 0..8 {if i==value.source_port_count as usize {value.source_ports[i]=packet.source_port;}}value.source_port_count+=1;}
                else {value.source_ports_truncated=1;}}
        }
    }}else{detail_miss(ASSOCIATION_MISS,bank,1);}
    unsafe {writer_add(w,u64::MAX);}
}
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
        }}else{miss(SOURCE_MISS);}
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
        let drop=blocked(&packet.source,now);
        record(&packet,unsafe{(*ctx.ctx).ingress_ifindex},len as u64,now,drop);
        if drop {count(DROPPED,1);return xdp_action::XDP_DROP;}
    }
    count(PASSED,1);xdp_action::XDP_PASS
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo)->! {loop{}}
#[unsafe(link_section="license")]
#[unsafe(no_mangle)]
static LICENSE:[u8;4]=*b"GPL\0";
