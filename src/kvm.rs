use std::{
    fs::OpenOptions,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::prelude::OpenOptionsExt,
    },
};

use anyhow::{ensure, Context, Result};
use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use nix::{ioctl_readwrite, ioctl_write_int_bad, libc::O_SYNC, request_code_none};
use tracing::debug;

use crate::snp_types::guest_policy::GuestPolicy;

const KVMIO: u8 = 0xAE;

pub struct KvmHandle {
    fd: OwnedFd,
}

impl KvmHandle {
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_SYNC)
            .open("/dev/kvm")
            .context("failed to open /dev/kvm")?;
        let fd = OwnedFd::from(file);

        ioctl_write_int_bad!(kvm_get_api_version, request_code_none!(KVMIO, 0x00));
        let res = unsafe { kvm_get_api_version(fd.as_raw_fd(), 0) };
        let version = res.context("failed to execute get_api_version")?;
        debug!(version, "determined kvm version");
        ensure!(version >= 12, "unsupported kvm api version ({version})");

        Ok(Self { fd })
    }

    pub fn create_snp_vm(&self) -> Result<VmHandle> {
        debug!("creating vm");

        ioctl_write_int_bad!(kvm_create_vm, request_code_none!(KVMIO, 0x01));
        let res = unsafe { kvm_create_vm(self.fd.as_raw_fd(), 3) };
        let raw_fd = res.context("failed to create vm")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Ok(VmHandle { fd })
    }
}

pub struct VmHandle {
    fd: OwnedFd,
}

impl VmHandle {
    unsafe fn memory_encrypt_op<'a>(
        &self,
        payload: KvmSevCmdPayload<'a>,
        sev_handle: Option<&SevHandle>,
    ) -> Result<KvmSevCmdPayload<'a>> {
        debug!("executing memory encryption operation");

        let mut cmd = KvmSevCmd {
            payload,
            error: 0,
            sev_fd: sev_handle.map(|sev_handle| sev_handle.fd.as_fd()),
        };

        ioctl_readwrite!(kvm_memory_encrypt_op, KVMIO, 0xba, u64);
        let res =
            kvm_memory_encrypt_op(self.fd.as_raw_fd(), &mut cmd as *mut KvmSevCmd as *mut u64);
        ensure!(cmd.error == 0);
        res.context("failed to execute memory encryption operation")?;

        Ok(cmd.payload)
    }

    pub fn sev_snp_init(&self) -> Result<()> {
        let mut data = KvmSnpInit {
            flags: KvmSnpInitFlags::empty(),
        };
        let payload = KvmSevCmdPayload::KvmSevSnpInit { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, None) };
        res.context("failed to initialize sev snp")?;
        Ok(())
    }

    pub fn sev_snp_launch_start(&self, policy: GuestPolicy, sev_handle: &SevHandle) -> Result<()> {
        debug!("starting snp launch");
        let mut data = KvmSevSnpLaunchStart {
            policy,
            ma_uaddr: 0,
            ma_en: 0,
            imi_en: 0,
            gosvw: [0; 16],
            _pad: [0; 6],
        };
        let payload = KvmSevCmdPayload::KvmSevSnpLaunchStart { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, Some(sev_handle)) };
        res.context("failed to start sev snp launch")?;
        Ok(())
    }

    pub fn sev_snp_dbg_decrypt(&self, gfn: u64) -> Result<[u8; 4096]> {
        debug!("debug decrypting");

        let mut page = [0xcc; 4096];

        let mut data = KvmSevSnpDbg {
            src_gfn: gfn,
            dst_uaddr: &mut page as *const [u8; 4096] as u64,
        };
        let payload = KvmSevCmdPayload::KvmSevSnpDbgDecrypt { data: &mut data };
        let res = unsafe { self.memory_encrypt_op(payload, None) };
        res.context("failed to debug decrypt")?;
        Ok(page)
    }
}

#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C, align(4096))]
pub struct Page {
    pub bytes: [u8; 4096],
}

impl Page {
    pub const ZERO: Page = Page { bytes: [0; 4096] };
}

impl Default for Page {
    fn default() -> Self {
        Self::ZERO
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmSegment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub ty: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    _padding: u8,
}

impl std::fmt::Debug for KvmSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmSegment")
            .field("base", &self.base)
            .field("limit", &self.limit)
            .field("selector", &self.selector)
            .field("ty", &self.ty)
            .field("present", &self.present)
            .field("dpl", &self.dpl)
            .field("db", &self.db)
            .field("s", &self.s)
            .field("l", &self.l)
            .field("g", &self.g)
            .field("avl", &self.avl)
            .field("unusable", &self.unusable)
            .finish()
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmDtable {
    pub base: u64,
    pub limit: u16,
    _padding: [u16; 3],
}

impl std::fmt::Debug for KvmDtable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmDtable")
            .field("base", &self.base)
            .field("limit", &self.limit)
            .finish()
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct KvmCpuidEntry2 {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    padding: [u32; 3],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmVcpuEvents {
    pub exception: KvmVcpuEventsException,
    pub interrupt: KvmVcpuEventsInterrupt,
    pub nmi: KvmVcpuEventsNmi,
    pub sipi_vector: u32,
    pub flags: u32,
    pub smi: KvmVcpuEventsSmi,
    reserved: [u8; 27],
    pub exception_has_payload: u8,
    pub exception_payload: u64,
}

impl std::fmt::Debug for KvmVcpuEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmVcpuEvents")
            .field("exception", &self.exception)
            .field("interrupt", &self.interrupt)
            .field("nmi", &self.nmi)
            .field("sipi_vector", &self.sipi_vector)
            .field("flags", &self.flags)
            .field("smi", &self.smi)
            .field("exception_has_payload", &self.exception_has_payload)
            .field("exception_payload", &self.exception_payload)
            .finish()
    }
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmVcpuEventsException {
    pub injected: u8,
    pub nr: u8,
    pub has_error_code: u8,
    pub pending: u8,
    pub error_code: u32,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmVcpuEventsInterrupt {
    pub injected: u8,
    pub nr: u8,
    pub soft: u8,
    pub shadow: u8,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmVcpuEventsNmi {
    pub injected: u8,
    pub pending: u8,
    pub masked: u8,
    pub pad: u8,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C)]
pub struct KvmVcpuEventsSmi {
    pub smm: u8,
    pub pending: u8,
    pub smm_inside_nmi: u8,
    pub latched_init: u8,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitUnknown {
    pub hardware_exit_reason: u64,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitIo {
    pub direction: u8,
    pub size: u8,
    pub port: u16,
    pub count: u32,
    /// relative to kvm_run start
    pub data_offset: u64,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitDebug {
    pub exception: u32,
    pub pad: u32,
    pub pc: u64,
    pub dr6: u64,
    pub dr7: u64,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitMmio {
    pub phys_addr: u64,
    pub data: [u8; 8],
    pub len: u32,
    pub is_write: u8,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitFailEntry {
    pub hardware_entry_failure_reason: u64,
    pub cpu: u32,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitInternalError {
    pub suberror: u32,
    pub ndata: u32,
    pub data: [u64; 16],
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitSystemEvent {
    pub ty: u32,
    pub ndata: u32,
    pub data: [u64; 16],
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitMsr {
    _error: u8, /* user -> kernel */
    _pad: [u8; 7],
    pub reason: KvmMsrExitReason, /* kernel -> user */
    pub index: u32,               /* kernel -> user */
    pub data: u64,                /* kernel <-> user */
}

bitflags! {
    #[derive(Pod, Zeroable)]
    #[repr(transparent)]
    pub struct KvmMsrExitReason: u32 {
        const INVAL = 1 << 0;
        const UNKNOWN = 1 << 1;
        const FILTER = 1 << 2;
    }
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitMemoryFault {
    pub flags: KvmExitMemoryFaultFlags,
    pub gpa: u64,
    pub size: u64,
}

bitflags! {
    #[derive(Pod, Zeroable)]
    #[repr(transparent)]
    pub struct KvmExitMemoryFaultFlags: u64 {
        const PRIVATE = 1 << 0;
    }
}

#[derive(Clone, Copy, Pod, Zeroable, Debug)]
#[repr(C, packed)]
pub struct KvmExitVmgexit {
    pub ghcb_msr: u64,
    pub error: u8,
}

bitflags! {
    #[repr(transparent)]
    pub struct KvmUserspaceMemoryRegionFlags: u32 {
        const KVM_MEM_LOG_DIRTY_PAGES = 1 << 0;
        const KVM_MEM_READONLY = 1 << 1;
        const KVM_MEM_PRIVATE = 1 << 2;
    }
}

pub struct SevHandle {
    fd: OwnedFd,
}

impl SevHandle {
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_SYNC)
            .open("/dev/sev")
            .context("failed to open /dev/sev")?;
        let fd = OwnedFd::from(file);
        Ok(Self { fd })
    }
}

#[repr(C)]
struct KvmSevCmd<'a, 'b> {
    pub payload: KvmSevCmdPayload<'a>,
    pub error: u32,
    pub sev_fd: Option<BorrowedFd<'b>>,
}

#[allow(clippy::enum_variant_names)]
#[repr(C, u32)]
// FIXME: Figure out which ones need `&mut T` and which ones need `&T`
pub enum KvmSevCmdPayload<'a> {
    KvmSevSnpInit { data: &'a mut KvmSnpInit } = 22,
    KvmSevSnpLaunchStart { data: &'a mut KvmSevSnpLaunchStart } = 23,
    KvmSevSnpDbgDecrypt { data: &'a mut KvmSevSnpDbg } = 28,
}

#[repr(C)]
pub struct KvmSnpInit {
    pub flags: KvmSnpInitFlags,
}

bitflags! {
    #[repr(transparent)]
    pub struct KvmSnpInitFlags: u64 {
        const KVM_SEV_SNP_RESTRICTED_INJET = 1 << 0;
        const KVM_SEV_SNP_RESTRICTED_TIMER_INJET = 1 << 1;
        const KVM_SEV_SNP_VMSA_REG_PROT = 1 << 2;
    }
}

#[repr(C)]
pub struct KvmSevSnpLaunchStart {
    /// Guest policy to use.
    pub policy: GuestPolicy,
    /// userspace address of migration agent
    pub ma_uaddr: u64,
    /// 1 if the migtation agent is enabled
    pub ma_en: u8,
    /// set IMI to 1.
    pub imi_en: u8,
    /// guest OS visible workarounds
    pub gosvw: [u8; 16],
    pub _pad: [u8; 6],
}

#[repr(C)]
pub struct KvmSevSnpDbg {
    src_gfn: u64,
    dst_uaddr: u64,
}

bitflags! {
    #[repr(transparent)]
    pub struct KvmGuestMemFdFlags: u64 {
        const HUGE_PMD = 1 << 0;
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct KvmLapicState {
    pub regs: [u8; 0x400],
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct KvmIoapicState {
    pub base_address: u64,
    pub ioregsel: u32,
    pub id: u32,
    pub irr: u32,
    pub pad: u32,
    pub redirtbl: [KvmIoapicStateRedirTableEntry; 24],
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C, packed)]
pub struct KvmIoapicStateRedirTableEntry {
    pub vector: u8,
    pub flags: u16,
    _reserved: [u8; 4],
    pub dest_id: u8,
}

#[derive(Debug)]
#[repr(C)]
pub struct KvmIrqfd<'a> {
    fd: BorrowedFd<'a>,
    gsi: u32,
    flags: KvmIrqfdFlags,
    resamplefd: Option<BorrowedFd<'a>>,
    _pad: [u8; 16],
}

bitflags! {
    pub struct KvmIrqfdFlags: u32 {
        const DEASSIGN = 1 << 0;
        const RESAMPLE = 1 << 1;
    }
}
