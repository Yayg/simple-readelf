#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define handle_error(msg) \
      do { perror(msg); exit(EXIT_FAILURE); } while (0)

static int validate(char *head)
{
    return (head[0] == ELFMAG0
            && head[1] == ELFMAG1
            && head[2] == ELFMAG2
            && head[3] == ELFMAG3);
}

void print_header(ElfW(Ehdr) *header)
{
  printf("Magic number: ");
  for (int i = 0; i < EI_NIDENT; ++i)
    printf("%02X ", header->e_ident[i]);
  printf("\n");
  printf("Class: %s\n",
       header->e_ident[EI_CLASS] == ELFCLASSNONE ? "None" :
      (header->e_ident[EI_CLASS] == ELFCLASS32 ? "ELF32" :
      (header->e_ident[EI_CLASS] == ELFCLASS64 ? "ELF64" :
       "Unknown")));
  printf("Data: %s\n",
   header->e_ident[EI_DATA] == ELFDATANONE ? "None" :
  (header->e_ident[EI_DATA] == ELFDATA2LSB ? "Two's complement, little-endian" :
  (header->e_ident[EI_DATA] == ELFDATA2MSB ? "Two's complement, big-endian" :
       "Unknown")));
  printf("Version: %u\n",
   header->e_ident[EI_VERSION] == EV_NONE           ? -1 : EV_CURRENT);
  printf("OS ABI: %s\n",
   header->e_ident[EI_OSABI] == ELFOSABI_NONE       ? "UNIX System V ABI" :
  (header->e_ident[EI_OSABI] == ELFOSABI_SYSV       ? "UNIX System V ABI" :
  (header->e_ident[EI_OSABI] == ELFOSABI_HPUX       ? "HP-UX ABI" :
  (header->e_ident[EI_OSABI] == ELFOSABI_NETBSD     ? "NetBSD ABI" :
  (header->e_ident[EI_OSABI] == ELFOSABI_LINUX      ? "Linux ABI" :
  (header->e_ident[EI_OSABI] == ELFOSABI_SOLARIS    ? "Solaris ABI" :
  (header->e_ident[EI_OSABI] == ELFOSABI_IRIX       ? "IRIX ABI" :
  (header->e_ident[EI_OSABI] == ELFOSABI_FREEBSD    ? "FreeBSD ABI" :
  (header->e_ident[EI_OSABI] == ELFOSABI_TRU64      ? "TRU64 UNIX ABI" :
  (header->e_ident[EI_OSABI] == ELFOSABI_ARM        ? "ARM architecture ABI" :
  (header->e_ident[EI_OSABI] == ELFOSABI_STANDALONE ? "Stand-alone (embedded) ABI" :
   "Unknown")))))))))));
  printf("ABI Version: %u\n", header->e_ident[EI_ABIVERSION]);
  printf("Type: %s\n",
   header->e_type == ET_NONE ?  "An unknown type" :
  (header->e_type == ET_REL  ?   "A relocatable file." :
  (header->e_type == ET_EXEC ?   "An executable file." :
  (header->e_type == ET_DYN  ?   "A shared object." :
  (header->e_type == ET_CORE ?   "A core file." :
   "Unknown")))));
  printf("Type: %s\n",
  (header->e_machine == EM_NONE     ? "An unknown machine." :
  (header->e_machine == EM_M32      ? "AT&T WE 32100." :
  (header->e_machine == EM_SPARC    ? "Sun Microsystems SPARC." :
  (header->e_machine == EM_386      ? "Intel 80386." :
  (header->e_machine == EM_68K      ? "Motorola 68000." :
  (header->e_machine == EM_88K      ? "Motorola 88000." :
  (header->e_machine == EM_860      ? "Intel 80860." :
  (header->e_machine == EM_MIPS     ? "MIPS RS3000 (big-endian only)." :
  (header->e_machine == EM_PARISC   ? "HP/PA." :
  (header->e_machine == EM_SPARC32PLUS ? "SPARC with enhanced instruction set." :
  (header->e_machine == EM_PPC      ? "PowerPC." :
  (header->e_machine == EM_PPC64    ? "PowerPC 64-bit." :
  (header->e_machine == EM_S390     ? "IBM S/390" :
  (header->e_machine == EM_ARM      ? "Advanced RISC Machines" :
  (header->e_machine == EM_SH       ? "Renesas SuperH" :
  (header->e_machine == EM_SPARCV9  ? "SPARC v9 64-bit." :
  (header->e_machine == EM_IA_64    ? "Intel Itanium" :
  (header->e_machine == EM_X86_64   ? "AMD x86-64" :
  (header->e_machine == EM_VAX      ? "DEC Vax." :
   "Unknown"))))))))))))))))))));
  printf("Object file version: %u\n", header->e_version);
  printf("Entry point virtual address: %p\n", (void*)header->e_entry);
  printf("Program header table file offset: %lu\n", header->e_phoff);
  printf("Section header table file offset: %lu\n", header->e_shoff);
  printf("Processor-specific flags: %u\n", header->e_flags);
  printf("ELF header size in bytes: %u\n", header->e_ehsize);
  printf("Program header table entry size: %u\n", header->e_phentsize);
  printf("Program header table entry count: %u\n", header->e_phnum);
  printf("Section header table entry size: %u\n", header->e_shentsize);
  printf("Section header table entry count: %u\n", header->e_shnum);
  printf("Section header string table index: %u\n", header->e_shstrndx);
}

void print_sections(void *file, ElfW(Ehdr) *header)
{
   ElfW(Shdr) *section_header = file + header->e_shoff;
   uint64_t name_table_section_index = header->e_shstrndx;
    if (name_table_section_index == SHN_XINDEX)
      name_table_section_index = section_header->sh_link;
    if (!name_table_section_index || name_table_section_index == SHN_UNDEF)
      exit(1);

    char *name_section = file + (section_header[name_table_section_index].sh_offset);

    for (int i = 0; i < header->e_shnum; ++i)
    {
      char * name = name_section + section_header[i].sh_name;
      printf("Name: %15s ", name);
      printf("Type: %3u ", section_header[i].sh_type);
      printf("Flag: %s%s%s ",
          section_header[i].sh_flags & SHF_WRITE ? "W" : " ",
          section_header[i].sh_flags & SHF_ALLOC ? "A" : " ",
          section_header[i].sh_flags & SHF_EXECINSTR ? "X" : " ");
      printf("Address: %8p ", (void*)section_header[i].sh_addr);
      printf("Offset %4lu ", section_header[i].sh_offset);
      printf("Size: %4lu ", section_header[i].sh_size);
      printf("Link: %2u ", section_header[i].sh_link);
      printf("Info: %2u ", section_header[i].sh_info);
      printf("Align: %2lu ", section_header[i].sh_addralign);
      printf("EntSize: %lu \n", section_header[i].sh_entsize);
    }

    printf("SHT_NULL = %d SHT_PROGBITS = %d SHT_SYMTAB = %d SHT_STRTAB = %d\n\
SHT_RELA = %d SHT_HASH = %d SHT_DYNAMIC = %d SHT_NOTE = %d\n\
SHT_NOBITS = %d SHT_REL = %d SHT_SHLIB = %d SHT_DYNSYM = %d\n\
SHT_LOPROC = %d SHT_HIPROC = %d SHT_LOUSER = %d SHT_HIUSER = %d\n",
     SHT_NULL,
     SHT_PROGBITS,
     SHT_SYMTAB,
     SHT_STRTAB,
     SHT_RELA,
     SHT_HASH,
     SHT_DYNAMIC,
     SHT_NOTE,
     SHT_NOBITS,
     SHT_REL,
     SHT_SHLIB,
     SHT_DYNSYM,
     SHT_LOPROC,
     SHT_HIPROC,
     SHT_LOUSER,
     SHT_HIUSER);
}

void print_sym_table(void *file,
                     ElfW(Shdr) *section_header,
                     ElfW(Sym) *sym_section,
                     ElfW(Shdr) *sym_header)
{
    int nb_sym = sym_header->sh_size / sym_header->sh_entsize;
    char *symname_section = file + section_header[sym_header->sh_link].sh_offset;
    for (int i = 0; i < nb_sym; ++i)
    {
      printf("Num: %d, ", i);
      printf("Value: %016lu, ", sym_section[i].st_value);
      printf("Size: %lu, ", sym_section[i].st_size);
      printf("Ndx: %u, ", sym_section[i].st_shndx);
      printf("Visibility: %9s, ",
      (sym_section[i].st_other == STV_DEFAULT    ? "Default" :
      (sym_section[i].st_other == STV_INTERNAL   ? "Internal" :
      (sym_section[i].st_other == STV_HIDDEN     ? "Hidden" :
      (sym_section[i].st_other == STV_PROTECTED  ? "Protected" :
      "Unknown")))));
      printf("Name: %s\n", symname_section + sym_section[i].st_name);
    }
}

void print_symbols(void *file, ElfW(Ehdr) *header)
{
   ElfW(Shdr) *section_header = file + header->e_shoff;
   uint64_t name_table_section_index = header->e_shstrndx;
    if (name_table_section_index == SHN_XINDEX)
      name_table_section_index = section_header->sh_link;
    if (!name_table_section_index || name_table_section_index == SHN_UNDEF)
      exit(1);

    ElfW(Sym) *dynsym_section = NULL;
    ElfW(Shdr) *dynsym_header = NULL;
    for (int i = 0; i < header->e_shnum; ++i)
    {
      if (section_header[i].sh_type == SHT_DYNSYM)
      {
        dynsym_section = file + (section_header[i].sh_offset);
        dynsym_header = &section_header[i];
        break;
      }
    }
    if (!dynsym_section)
      exit(2);
    printf(".dynsym\n");
    print_sym_table(file, section_header, dynsym_section, dynsym_header);

    ElfW(Sym) *symtab_section = NULL;
    ElfW(Shdr) *symtab_header = NULL;
    for (int i = 0; i < header->e_shnum; ++i)
    {
      if (section_header[i].sh_type == SHT_SYMTAB)
      {
        symtab_section = file + (section_header[i].sh_offset);
        symtab_header = &section_header[i];
        break;
      }
    }
    if (!symtab_section)
      exit(2);
    printf(".symtab\n");
    print_sym_table(file, section_header, symtab_section, symtab_header);
}

void print_program(void *file, ElfW(Ehdr) *header)
{
  ElfW(Phdr) *program_header = file + header->e_phoff;
  for (int i = 0; i < header->e_phnum; ++i)
  {
    printf("Type: %8s, ",
      program_header->p_type == PT_NULL     ? "NULL" :
     (program_header->p_type == PT_LOAD     ? "LOAD" :
     (program_header->p_type == PT_DYNAMIC  ? "DYNAMIC" :
     (program_header->p_type == PT_INTERP   ? "INTERP" :
     (program_header->p_type == PT_NOTE     ? "NOTE" :
     (program_header->p_type == PT_SHLIB    ? "SHLIB" :
     (program_header->p_type == PT_PHDR     ? "PHDR" :
     (program_header->p_type == PT_LOPROC   ? "LOPROC" :
     (program_header->p_type == PT_HIPROC   ? "HIPROC" :
     (program_header->p_type == PT_GNU_STACK ? "GNU_STACK" :
      "Unknown"))))))))));
    printf("Offset: %4lu, ",  program_header->p_offset);
    printf("VAddr: %8p, ",    (void*)program_header->p_vaddr);
    printf("PAddr: %8p, ",    (void*)program_header->p_paddr);
    printf("FileSize: %8p, ", (void*)program_header->p_filesz);
    printf("MemSize: %8p, ",  (void*)program_header->p_memsz);
    printf("Flags: %s%s%s, ",
       program_header->p_flags & PF_R ? "R" : " ",
       program_header->p_flags & PF_W ? "W" : " ",
       program_header->p_flags & PF_X ? "E" : " ");
    printf("PAlign: %lu\n", program_header->p_align);
    program_header = (void*) ((char*) program_header + header->e_phentsize);
  }
}

void print_segment(void *file, ElfW(Ehdr) *header)
{
  ElfW(Phdr) *program_header = file + header->e_phoff;
  for (int i = 0; i < header->e_phnum; ++i)
  {
    printf("%01d    ", i);
    ElfW(Shdr) *section_header = file + header->e_shoff;
    ElfW(Shdr) *name_section = file + section_header[header->e_shstrndx].sh_offset;
    for (int j = 0; j < header->e_shnum; ++i)
    {
      char *name = (void*) name_section + section_header[j].sh_name;

    }
  }
}

int main(int argc, char *argv[])
{
  if (argc < 3) {
    puts("Usage: simple-readelf [-hSsl] FILE");
    puts("Usage: simple-readelf (-h|-S|-s|-l) FILE");
    puts("  -h print elf headers");
    puts("  -S print elf sections");
    puts("  -s print symbol table");
    puts("  -l print program headers");
    return 1;
  }
   /* The file descriptor. */
  int fd;
  /* Information about the file. */
  struct stat s;
  int status;
  size_t size;

  /* Open the file for reading. */
  fd = open (argv[2], O_RDONLY);
  if (fd == -1)
    handle_error("open");

  /* Get the size of the file. */
  status = fstat (fd, & s);
  if (status == -1) /* To obtain file size */
    handle_error("fstat");
  size = s.st_size;

  /* Memory-map the file. */
  void *file = mmap (NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (file == MAP_FAILED)
    handle_error("mmap");
  if (!validate(file))
  {
    puts("Not a elf file");
    return 1;
  }
  ElfW(Ehdr) *header = file;
  if (!strcmp(argv[1], "-h"))
    print_header(header);
  if (!header->e_shoff)
      return 1;
  if (!strcmp(argv[1], "-S"))
    print_sections(file, header);
  if (!strcmp(argv[1], "-s"))
    print_symbols(file, header);
  if (!strcmp(argv[1], "-l"))
    print_program(file, header);
  return 0;
}
