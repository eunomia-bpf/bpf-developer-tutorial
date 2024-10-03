pub use libc::Elf64_Addr;
pub use libc::Elf64_Half;
pub use libc::Elf64_Off;
pub use libc::Elf64_Phdr;
pub use libc::Elf64_Shdr;
pub use libc::Elf64_Sxword;
pub use libc::Elf64_Sym;
pub use libc::Elf64_Word;
pub use libc::Elf64_Xword;

pub use libc::Elf64_Ehdr;
pub use libc::ET_CORE;
pub use libc::ET_DYN;
pub use libc::ET_EXEC;
pub use libc::ET_HIPROC;
pub use libc::ET_LOPROC;
pub use libc::ET_NONE;
pub use libc::ET_REL;

pub use libc::PF_R;
pub use libc::PF_W;
pub use libc::PF_X;

pub use libc::PT_DYNAMIC;
pub use libc::PT_GNU_EH_FRAME;
pub use libc::PT_GNU_STACK;
pub use libc::PT_HIOS;
pub use libc::PT_HIPROC;
pub use libc::PT_INTERP;
pub use libc::PT_LOAD;
pub use libc::PT_LOOS;
pub use libc::PT_LOPROC;
pub use libc::PT_NOTE;
pub use libc::PT_NULL;
pub use libc::PT_PHDR;
pub use libc::PT_SHLIB;
pub use libc::PT_TLS;

pub const SHN_UNDEF: u16 = 0;

pub const STT_FUNC: u8 = 2;
