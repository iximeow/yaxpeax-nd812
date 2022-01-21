//! # `yaxpeax-nd812`, a decoder for the ND812 instruction set
//!
//! the ND812 instruction set is used in the Nuclear Data ND812 microcomputer, first introduced in
//! 1970. the ND812 and associated additional hardware (such as the ND4410) were used for
//! scientific applications and it seems relatively few programs for this equipment has survived to
//! the present day.
//!
//! interesting for yaxpeax reasons, the ND812 is a 12-bit machine. `yaxpeax-nd812` decodes units
//! of [`ND812Word`], consulting only the low 12 bits of the contained `u16`. `ND812Word` then
//! requires an `impl Reader<u16, ND812Word>` to decode from; there is a default impl to read
//! `ND812Word` from a regular `&[u8]`, but a more comprehensive `ND812` simulator would need to
//! also reproduce the wrap-at-4k-boundary behavior from the real hardware.
//!
//! the actual packing of 12-bit words may also be of interest. i couldn't find any `ND812`
//! programs online as binary, even as binary images to be loaded by simulators - i couldn't really
//! find any `ND812` simulators available online either. so my best guess for a reasonable binary
//! format is to do what people do with PDP-8 (also 12-bit) binary blobs, with 12-bit words in
//! two-byte units of memory.
//!
//! lastly, thank goodness for `bitsavers.org`. i found many of the manuals and documents for the
//! `ND812` in scattered places online, but bitsavers has them all in one place. the reference
//! there helped me answer a few questions about missing documents, and led me to finding program
//! `ND41-1085` in the `IM41-1085` manual for x-ray analysis. it turned out that the best test
//! cases were reference programs from Nuclear Data themselves.
//!
//! reference materials:
//! ```text
//! shasum -a 256 IM*
//! 3a4ccbdd898ff071636d14af908e2386d6204b77d39a546f416f40ad7ad890fa
//!   IM41-0001_Software_Instruction_Manual_BASC-12_General_Assembler_Jan71.pdf
//! 39dcb814862c385986aee6ff31b4f0a942e9ff8dcaac0046cbcba55f052d42e5
//!   IM41-0002-04_Software_Instruction_Manual_ND812_Symbolic_Text_Editor_Nov72.pdf
//! d5380bed1407566b491d00e654bc7967208fa71ef6daa7ec82e73805f671ff0a
//!   IM41-0059-00_NUTRAN_User_and_Programmers_Guide_Nov72.pdf
//! f508a4bb6a834352b1a391ac0dd851201dd6a6a5cfa6eec53aa4c6dbf86e088a
//!   IM41-1062-00_Software_Instruction_Manual_ND4410_Low_High_Speed_Paper_Tape_IO_Overlay_Program_Apr72.pdf
//! a1364c23ffadc4414c7b905cfce7cd4c0914a5b0d29b1726246a9d5d68d0aa7a
//!   IM41-8001-01_Software_Instruction_Manual_ND812_Diagnostics_Feb72.pdf
//! 62013481aab174473ae1cbaed35d02eb7f22a05acd6c56ae36d166502925cb25
//!   IM41-8045-00_Software_Instruction_Manual_Hardware_Multipy_Divide_Test_Jun72.pdf
//! 3cf00d268cab96eebda973b53b870fe761e83d2e61a733860094920b17d84b22
//!   IM88-0481-02_Hardware_Instruction_Manual_ND812_Teletype_Auto_Loader_Interface_Sep72.pdf
//! ```
//!
//! ## usage
//!
//! the fastest way to decode an nd812 instruction is through
//! [`InstDecoder::decode_slice()`]:
//! ```
//! use yaxpeax_nd812::InstDecoder;
//!
//! let inst = InstDecoder::decode_u16(&[0o1122]).unwrap();
//!
//! assert_eq!("adr j", inst.to_string());
//! ```
//!
//! opcodes and operands are available on the decoded instruction, as well as its length and
//! operand count:
//! ```
//! use yaxpeax_nd812::{InstDecoder, Operand, Opcode};
//!
//! let inst = InstDecoder::decode_u16(&[0o1123]).unwrap();
//!
//! assert_eq!("sbr j", inst.to_string());
//! assert_eq!(inst.operand_count(), 2);
//! assert_eq!(inst.len(), 1);
//! assert_eq!(inst.opcode(), Opcode::SubR);
//! assert_eq!(inst.operand(0), Operand::R);
//! assert_eq!(inst.operand(1), Operand::J);
//! ```
//!
//! additionally, `yaxpeax-nd812` implements `yaxpeax-arch` traits for generic use, such as
//! [`yaxpeax_arch::LengthedInstruction`]. [`yaxpeax_arch::Arch`] is implemented by
//! the unit struct [`ND812`].
//!
//! ## `#![no_std]`
//!
//! `yaxpeax-nd812` should support `no_std` usage, but this is entirely untested.

#![no_std]

mod display;

use yaxpeax_arch::{AddressDiff, Arch, Decoder, LengthedInstruction, Reader, ReadError, U8Reader};

/// a trivial struct for [`yaxpeax_arch::Arch`] to be implemented on. it's only interesting for the
/// associated type parameters.
#[derive(Hash, Eq, PartialEq, Debug, Copy, Clone)]
pub struct ND812;

/// a 12-bit word, as used in the `nd812`.
#[derive(Copy, Clone, Debug, Hash, Eq, Ord, PartialOrd, PartialEq)]
#[repr(transparent)]
pub struct ND812Word(u16);

impl ND812Word {
    /// get the value of this 12-bit word as a u16
    pub fn value(&self) -> u16 {
        self.0
    }

    /// create an `ND812Word` from a value `v`
    ///
    /// returns `None` if `v` is out of range for an `ND812Word` (is larger than `0o7777`, or in
    /// base 16, `0x0fff`)
    pub fn new(v: u16) -> Option<Self> {
        if v > 0o7777 {
            None
        } else {
            Some(ND812Word(v))
        }
    }
}

impl core::fmt::Display for ND812Word {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Arch for ND812 {
    type Address = u16;
    type Word = ND812Word;
    type Instruction = Instruction;
    type Decoder = InstDecoder;
    type DecodeError = DecodeError;
    type Operand = Operand;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// no input available but the instruction would require at least one more word to decode
    ExhaustedInput,
    /// the word(s) to decode this instruction do not map to a defined instruction
    Undefined,
}

impl From<yaxpeax_arch::ReadError> for DecodeError {
    fn from(_e: yaxpeax_arch::ReadError) -> Self {
        DecodeError::ExhaustedInput
    }
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use yaxpeax_arch::DecodeError;
        f.write_str(self.description())
    }
}

impl yaxpeax_arch::DecodeError for DecodeError {
    fn data_exhausted(&self) -> bool {
        *self == DecodeError::ExhaustedInput
    }
    fn bad_opcode(&self) -> bool {
        *self == DecodeError::Undefined
    }
    fn bad_operand(&self) -> bool {
        *self == DecodeError::Undefined
    }
    fn description(&self) -> &'static str {
        match self {
            DecodeError::ExhaustedInput => "exhausted input",
            DecodeError::Undefined => "undefined encoding",
        }
    }
}

/// a wrapper describing one of four (three optional) memory fields in an `nd812`. some `nd812`
/// documentation refers to these as "stacks" of memory.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
pub struct MemoryField {
    value: u8
}

impl MemoryField {
    fn new(which: u8) -> Self {
        assert!(which < 4);

        MemoryField { value: which }
    }

    /// get the bits to select this `field` as encoded in an `nd812` instruction. default field is
    /// `0`, with possible alternate field `1`, `2`, and `3`. the `nd812` does not support more
    /// than four total field, so this function will never return a value of 4 or above.
    pub fn num(&self) -> u8 {
        self.value
    }
}

/// an `nd812` instruction.
///
/// `nd812` instructions have an [`Opcode`] and up to three [`Operand`]s. they are one or two
/// `ND812Word` long.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Instruction {
    /// the operation of this instruction.
    opcode: Opcode,
    operands: [Operand; 3],
    /// the nd812 "field" this instruction references. if this is present, memory referenced will
    /// be with respect to this 4096-word field of memory. a `field` of memory, to the `nd812`, is
    /// a linear region of memory - this is also called a "stack" in some documentation. even so,
    /// there is no "stack pointer" nor "growth" (upward or downward) notions.
    ///
    /// if there is a field selected, and the instruction is `jmp` or `jps`, this field will be
    /// made default for instructions after this.
    referenced_field: Option<MemoryField>,
    length: u8,
}

impl Default for Instruction {
    fn default() -> Instruction {
        Instruction {
            opcode: Opcode::STOP,
            operands: [Operand::Nothing, Operand::Nothing, Operand::Nothing],
            referenced_field: None,
            length: 0,
        }
    }
}

impl Instruction {
    fn reset_operands(&mut self) {
        self.operands = [Operand::Nothing, Operand::Nothing, Operand::Nothing];
    }

    /// the length of this instruction, in terms of [`ND812Word`].
    pub fn len(&self) -> u8 {
        self.length
    }

    /// get the number of operands in this instruction.
    ///
    /// calls to `Instruction::operand` for indices between 0 and this value will return an operand
    /// other than `Operand::Nothing`.
    pub fn operand_count(&self) -> u8 {
        if self.operands[0] == Operand::Nothing {
            0
        } else if self.operands[1] == Operand::Nothing {
            1
        } else {
            2
        }
    }

    /// get the `Operand` at the provided index.
    ///
    /// indices above `3` will always yield `Operand::Nothing`.
    pub fn operand(&self, idx: u8) -> Operand {
        self.operands.get(idx as usize).map(|x| *x).unwrap_or(Operand::Nothing)
    }

    /// get the `Opcode` of this instruction.
    pub fn opcode(&self) -> Opcode {
        self.opcode
    }
}

impl LengthedInstruction for Instruction {
    type Unit = AddressDiff<<ND812 as Arch>::Address>;
    fn min_size() -> Self::Unit {
        AddressDiff::from_const(1)
    }
    fn len(&self) -> Self::Unit {
        AddressDiff::from_const(self.length as u16)
    }
}

impl yaxpeax_arch::Instruction for Instruction {
    fn well_defined(&self) -> bool { true }
}

/// an operand for an `nd812` instruction.
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub enum Operand {
    /// no operand in this position.
    ///
    /// reaching this as a user of `yaxpeax_nd812` is almost certainly a bug. `Instruction::operand`
    /// will return `None` rather than `Operand::Nothing`.
    Nothing,
    /// the `J` register
    J,
    /// the `K` register
    K,
    /// the `JK` register
    JK,
    /// the `R` register
    R,
    /// the `S` register
    S,
    /// the `RS` register
    RS,
    /// the `OverflowBit` register
    OverflowBit,
    /// the `FlagBit` register
    FlagBit,
    /// memory access to `pc` plus the given signed offset, in the range `[-64, 64]` (inclusive).
    /// additionally, the displacement may be indirect; `pc + offset` may be used as a pointer.
    Displacement(bool, i8),
    /// memory access to the absolute u12 address, in the range `[0, 4095]` (inclusive).
    /// additionally, the displacement may be indirect; `offset` may be used as a pointer.
    ///
    /// in practice, instructions with an `Absolute` operand also may have an alternate field
    /// selected, so correct interpretation of this operand will need to consult the referenced
    /// field as well.
    Absolute(bool, u16),
    /// a literal value encoded in an instruction (modern instruction sets would call this an
    /// `immediate`)
    Literal(u8),
}

/// an `nd812` instruction's operation.
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub enum Opcode {
    /// `Stop Execution`
    STOP,
    /// `One cycle delay`
    IDLE,
    /// `Cassette High-Speed Forward EOT (TWIO)`
    CHSF,
    /// `Cassette Space Forward to File Mark (TWIO)`
    CSPF,
    /// `Cassette Skip on File Mark (TWIO)`
    CSFM,
    /// `Cassette Skip if EOT (TWIO)`
    CSET,
    /// `Cassette High-Speed Reverse BOT (TWIO)`
    CHSR,
    /// `Cassette Skip No-Error (TWIO)`
    CSNE,
    /// `Cassette Skip if On-Line Tape Ready (TWIO)`
    CSTR,
    /// `Cassette Skip if BOT (TWIO)`
    CSBT,
    /// `Cassette Clear All Flags (TWIO)`
    CCLF,
    /// `Cassette Skip if Read Ready (TWIO)`
    CSRR,
    /// `Cassette Read to J (TWIO)`
    CRDT,
    /// `Cassette Write File Mark (TWIO)`
    CWFM,
    /// `Cassette Skip if Write Ready (TWIO)`
    CSWR,
    /// `Cassette Write Transfer (TWIO)`
    CWRT,
    /// `Two Word Skip if Memory Not Equal`
    ///
    /// `yaxpeax-nd812` records the register to operate against as an operand, `Operand::J` or
    /// `Operand::K`.
    TWSM,
    TWDSZ,
    TWISZ,
    /// `Two Word Subtract`
    ///
    /// `yaxpeax-nd812` records the register to operate against as an operand, `Operand::J` or
    /// `Operand::K`.
    TWSB,
    /// `Two Word Add`
    ///
    /// `yaxpeax-nd812` records the register to operate against as an operand, `Operand::J` or
    /// `Operand::K`.
    TWAD,
    /// `Two Word Load`
    ///
    /// `yaxpeax-nd812` records the register to operate against as an operand, `Operand::J` or
    /// `Operand::K`.
    TWLD,
    /// `Two Word Store`
    ///
    /// `yaxpeax-nd812` records the register to operate against as an operand, `Operand::J` or
    /// `Operand::K`.
    TWST,
    /// `Two Word Unconditional Jump`
    TWJMP,
    /// `Two Word Jump Subroutine`
    TWJPS,
    /// `Multiply J by K`
    MPY,
    /// `Divide J and K by R`
    DIV,
    /// `Read Flag, Overflow from J`
    RFOV,
    /// `Disable All Interrupt Levels`
    IOFF,
    /// `Enable Level H Only`
    IONH,
    /// `Enable Interrupt Levels H & A`
    IONA,
    /// `Enable Interrupt Levels H & B`
    IONB,
    /// `Enable All Interrupt Levels`
    IONN,
    /// `Load J from Switches`
    LJSW,
    /// `Load J from Status Register`
    LJST,
    /// `And J, K, into <op0>`
    ///
    /// `yaxpeax-nd812` records the destination as an operand, `Operand::J`, `Operand::K`, or
    /// `Operand::JK`
    And,
    /// `Load <op0> into <op1>`
    ///
    /// `yaxpeax-nd812` records the source and destination both as operands. operands will be one
    /// of the following pairs:
    /// * `R, J`
    /// * `J, R`
    /// * `S, K`
    /// * `K, S`
    /// * `K, J`
    /// * `RS, JK`
    /// * `JK, RS`
    Load, // load op[0] from [1]
    /// `Exchange <op0> and <op1>`
    ///
    /// `yaxpeax-nd812` records the source and destination both as operands. operands will be one
    /// of the following pairs:
    /// * `J, R`
    /// * `K, S`
    /// * `JK, RS`
    Exchange, // exchange op[0], op[1]
    /// `J + K to <op0>`
    ///
    /// `yaxpeax-nd812` records the destination as an operand, `Operand::J`, `Operand::K`, or
    /// `Operand::JK`
    AddJK, // `op[0] + op[1] to op[2]`
    /// `J - K to <op0>`
    ///
    /// `yaxpeax-nd812` records the destination as an operand, `Operand::J` or `Operand::K`
    SubJK, // `op[0] - op[1] to op[2]`
    /// `<op0> + <op1> to <op1>`
    ///
    /// `yaxpeax-nd812` records the source and destination both as operands:
    /// * `op0` can be `Operand::R` or `Operand::S`
    /// * `op1` can be `Operand::J` or `Operand::K`
    AddR, // `op[0] + op[1] to op[2]`
    /// `<op0> - <op1> to <op1>`
    ///
    /// `yaxpeax-nd812` records the source and destination both as operands:
    /// * `op0` can be `Operand::R` or `Operand::S`
    /// * `op1` can be `Operand::J` or `Operand::K`
    SubR, // `op[0] - op[1] to op[2]`
    /// `-(J + K) to <op0>`
    ///
    /// `yaxpeax-nd812` records the destination as an operand, `Operand::J`, `Operand::K`, or
    /// `Operand::JK`
    NegAddJK, // `-(op[0] + op[1]) to op[2]`
    /// `K - J to <op0>`
    ///
    /// `yaxpeax-nd812` records the destination as an operand, `Operand::J` or `Operand::K`
    NegSubJK, // `(op[1] - op[0]) to op[2]`
    /// `-(<op0> + <op1>) to <op1>`
    ///
    /// `yaxpeax-nd812` records the source and destination both as operands:
    /// * `op0` can be `Operand::R` or `Operand::S`
    /// * `op1` can be `Operand::J` or `Operand::K`
    NegAddR, // `-(op[0] + op[1]) to op[2]`
    /// `<op1> - <op0> to <op1>`
    ///
    /// `yaxpeax-nd812` records the source and destination both as operands:
    /// * `op0` can be `Operand::R` or `Operand::S`
    /// * `op1` can be `Operand::J` or `Operand::K`
    NegSubR, // `(op[1] - op[0]) to op[2]`
    /// `Shift <op0> left N`
    ///
    /// `yaxpeax-nd812` records the register as an operand, either `Operand::J`, `Operand::K`, or
    /// `Operand::JK`.
    Shift, // `j <<= N`, what is N?
    /// `Rotate <op0> left N`
    ///
    /// `yaxpeax-nd812` records the register as an operand, either `Operand::J`, `Operand::K`, or
    /// `Operand::JK`.
    Rotate, // `j <<= N`, what is N?
    /// `Skip if Flag Register One`
    ///
    /// `yaxpeax-nd812` records the register as an operand, either `Operand::FlagBit` or
    /// `Operand::Overflow`, or J, K, JK,
    SNZ,
    /// `Skip if Flag Register Zero`
    ///
    /// `yaxpeax-nd812` records the register as an operand, either `Operand::FlagBit` or
    /// `Operand::OverflowBit`, or J, K, JK,
    SIZ,
    ///
    /// `yaxpeax-nd812` records the register as an operand, either `Operand::FlagBit` or
    /// `Operand::OverflowBit`, or J, K, JK,
    CLR,
    ///
    /// `yaxpeax-nd812` records the register as an operand, either `Operand::FlagBit` or
    /// `Operand::OverflowBit`, or J, K, JK
    CMP,
    ///
    /// `yaxpeax-nd812` records the register as an operand, either `Operand::FlagBit` or
    /// `Operand::OverflowBit`, or J, K, JK
    SET,
    /// `Skip on Power Low`
    SKPL,
    /// `Powerfail System On`
    PION,
    /// `Powerfail System Off`
    PIOF,
    ///
    /// `yaxpeax-nd812` records the register as an operand, either `Operand::FlagBit` or
    /// `Operand::OverflowBit`, or J, K, JK
    SIP,
    ///
    /// `yaxpeax-nd812` records the register as an operand, either `Operand::FlagBit` or
    /// `Operand::OverflowBit`, or J, K, JK
    INC,
    ///
    /// `yaxpeax-nd812` records the register as an operand, either `Operand::FlagBit` or
    /// `Operand::OverflowBit`, or J, K, JK
    SIN,
    ///
    /// `yaxpeax-nd812` records the register as an operand, either `Operand::FlagBit` or
    /// `Operand::OverflowBit`, or J, K, JK
    NEG,
    /// `AND with J, Forward`
    ANDF,
    /// `AND J Literal`
    ANDL,
    /// `ADD J Literal`
    ADDL,
    /// `SUBTRACT J Literal`
    SUBL,
    /// `Skip if J not Equal Memory`
    SMJ,
    /// `Decrement Memory and Skip`
    DSZ,
    /// `Increment Memory and Skip`
    ISZ,
    /// `Subtract from J`
    SBJ,
    /// `Add to J`
    ADJ,
    /// `Load J`
    LDJ,
    /// `Store J`
    STJ,
    /// `Unconditional Jump`
    JMP,
    /// `Unconditional Skip`
    SKIP,
    /// `Jump Subroutine`
    JPS,
    /// `Execute Displaced Instruction`
    XCT,
    /// `TTY Keyboard-Reader Fetch`
    TIF,
    /// `TTY Keyboard Into J`
    TIR,
    /// `TIR and TIF combined`
    TRF,
    /// `TTY Skip if Keyboard Ready`
    TIS,
    /// `Clear printer/punch flag`
    TOC,
    /// `Clear printer/punch flag, load printer/punch buffer from J and print/punch`
    TOP,
    /// `TOP and TOC combined`
    TCP,
    /// `TTY Skip if Printer-Punch Reader`
    TOS,
    /// `HS Reader - Fetch`
    HIF,
    /// `HS Reader - CLR Flag, Read Buffer`
    HIR,
    /// `HIR and HIF combined`
    HRF,
    /// `Skip if HS reader flag = 1`
    HIS,
    /// `HS Punch - Punch On`
    HOP,
    /// `HS Punch - CLR Flag, Load Buffer`
    HOL,
    /// `HS Punch - Load and Punch`
    HLP,
    /// `HS Punch - Skip if punch ready`
    HOS,
    /// `Cassette - Unit 1 On-Line`
    CSLCT1,
    /// `Cassette - Unit 2 On-Line`
    CSLCT2,
    /// `Cassette - Unit 3 On-Line`
    CSLCT3,
    /// `Load JPS Reg from J, INT Reg from K`
    LDREG,
    /// `Load JPS Reg to J, INT Reg to K`
    LDJK,
    /// `Restore JPS and INT field bits`
    RJIB,
}

/// the ND812 uses a modified character set to pack two characters into 12-bit words; each
/// character is *6* bits.
///
/// TODO: not yet sure how this maps to ascii; `Appendix C` describes `A` as `ASCII CODE 301` -
/// doesn't match as octal or.. anything else. the whole character set is reproduced here, for
/// reference. this all DOES line up with ascii if ND812 assumes ascii has the high bit set?
pub const ND812_CHARSET: &[u8] = &[
    b'A', b'B', b'C', b'D', b'E', b'F',
    b'G', b'H', b'I', b'J', b'K', b'L',
    b'M', b'N', b'O', b'P', b'Q', b'R',
    b'S', b'T', b'U', b'V', b'W', b'X',
    b'Y', b'Z', b'0', b'1', b'2', b'3',
    b'4', b'5', b'6', b'7', b'8', b'9',
    b'$', b'*', b'+', b'!', b'-', b'.',
    b'/', b';', b'=', b' ', b'\t', b'\n',
    0x0c, b'\r', 0o377
];

/// an `nd812` instruction decoder.
///
/// there are no decode options for `nd812`, so this is a trivial struct that exists only for the
/// [`yaxpeax_arch::Decoder`] trait impl.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstDecoder { }

pub struct ND812Reader<T> {
    underlying: T,
    start: u16,
    mark: u16,
    offset: u16,
}

impl<'a> ND812Reader<&'a [u16]> {
    pub fn of_u16(data: &'a [u16]) -> Self {
        ND812Reader {
            underlying: data,
            start: 0,
            mark: 0,
            offset: 0,
        }
    }
}

impl<'a> Reader<u16, ND812Word> for ND812Reader<&'a [u16]> {
    fn next(&mut self) -> Result<ND812Word, ReadError> {
        if let Some(word) = self.underlying.get(self.offset as usize) {
            if word & 0xf000 != 0 {
                return Err(ReadError::IOError("invalid nd812 word in u16 data: bits in 12-15 are set"));
            }

            self.offset += 1;
            Ok(ND812Word(word & 0o7777))
        } else {
            Err(ReadError::ExhaustedInput)
        }
    }

    fn next_n(&mut self, buf: &mut [ND812Word]) -> Result<(), ReadError> {
        if buf.len() > self.underlying.len() - self.offset as usize {
            return Err(ReadError::ExhaustedInput);
        }

        // there's at least enough data, though some of it could be invalid...
        // TODO: this will result in an error potentially consuming data without indicating how
        // much data was consumed. not good!
        for i in 0..buf.len() {
            buf[i] = self.next()?;
        }

        Ok(())
    }

    fn mark(&mut self) {
        self.mark = self.offset;
    }

    fn offset(&mut self) -> u16 {
        self.offset - self.mark
    }

    fn total_offset(&mut self) -> u16 {
        self.offset - self.start
    }
}

impl<'a> ND812Reader<U8Reader<'a>> {
    pub fn of_u8(data: &'a [u8]) -> Self {
        ND812Reader {
            underlying: U8Reader::new(data),
            start: 0,
            mark: 0,
            offset: 0,
        }
    }
}

impl<'a> Reader<u16, ND812Word> for ND812Reader<U8Reader<'a>> {
    fn next(&mut self) -> Result<ND812Word, ReadError> {
        let high = Reader::<u16, u8>::next(&mut self.underlying)?;
        let low = Reader::<u16, u8>::next(&mut self.underlying)?;
        self.offset += 1;
        Ok(ND812Word(u16::from_le_bytes([low, high])))
    }

    fn next_n(&mut self, buf: &mut [ND812Word]) -> Result<(), ReadError> {
        // TODO: this will result in an error potentially consuming data without indicating how
        // much data was consumed. not good!
        for i in 0..buf.len() {
            buf[i] = self.next()?;
        }

        Ok(())
    }

    fn mark(&mut self) {
        Reader::<u16, u8>::mark(&mut self.underlying);
        self.mark = self.offset;
    }

    fn offset(&mut self) -> u16 {
        self.offset - self.mark
    }

    fn total_offset(&mut self) -> u16 {
        self.offset - self.start
    }
}

/*
impl Reader<u16, ND812Word> for ND812Reader<U16Reader> {
}
*/

impl InstDecoder {
    /// decode a slice of bytes into an instruction (or error)
    ///
    /// this is just a higher-level interface to the [`InstDecoder`] impl of
    /// [`yaxpeax_arch::Decoder`].
    pub fn decode_slice(data: &[u8]) -> Result<Instruction, <ND812 as Arch>::DecodeError> {
        InstDecoder::default()
            .decode(&mut ND812Reader::of_u8(data))
    }

    /// decode a slice of `u16` into an instruction (or error)
    ///
    /// this is just a higher-level interface to the [`InstDecoder`] impl of
    /// [`yaxpeax_arch::Decoder`].
    pub fn decode_u16(data: &[u16]) -> Result<Instruction, <ND812 as Arch>::DecodeError> {
        InstDecoder::default()
            .decode(&mut ND812Reader::of_u16(data))
    }
}

impl Default for InstDecoder {
    fn default() -> Self {
        InstDecoder { }
    }
}

impl Decoder<ND812> for InstDecoder {
    fn decode_into<T: Reader<<ND812 as Arch>::Address, <ND812 as Arch>::Word>>(&self, inst: &mut Instruction, words: &mut T) -> Result<(), <ND812 as Arch>::DecodeError> {
        inst.length = 0;
        inst.reset_operands();
        words.mark();
        let word = words.next()?;

        let operation = word.0 >> 8;

        if word.0 & 0o7700 == 0 {
            inst.opcode = Opcode::STOP;
            inst.length = words.offset() as u8;

            return Ok(());
        }

        match operation {
            0b0000 |
            0b0001 => {
                // two word instruction
                let address = words.next()?;
                let opc = (word.0 >> 5) & 0b0001111;
                let field = word.0 & 0b11;
                let change_field = (word.0 & 0b0100) != 0;
                let kj = (word.0 & 0b1000) != 0;
                let ind = (word.0 & 0b10000) != 0;

                if word.0 < 0o0240 {
                    // unallocated
                    // cassette two-word i/o op
                } else if word.0 == 0o0740 {
                    // TWIO (two word i/o)
                    let opc = address.0;

                    const OPC: &[Option<Opcode>] = &[
                        None, Some(Opcode::CHSF), Some(Opcode::CSPF), None, Some(Opcode::CSFM), None, None, None,
                        Some(Opcode::CSET), None, None, None, None, None, None, None,
                        None, Some(Opcode::CHSR), Some(Opcode::CSNE), None, Some(Opcode::CSTR), None, None, None,
                        Some(Opcode::CSBT), None, None, None, None, None, None, None,
                        None, Some(Opcode::CCLF), Some(Opcode::CSRR), None, Some(Opcode::CRDT), None, None, None,
                        None, Some(Opcode::CWFM), Some(Opcode::CSWR), None, Some(Opcode::CWRT), None, None, None,
                    ];

                    if opc < 0o100 {
                        return Err(DecodeError::Undefined);
                    }

                    let opc = opc - 0o0100;
                    inst.opcode = *OPC.get(opc as usize).and_then(|x| x.as_ref()).ok_or(DecodeError::Undefined)?;
                } else {
                    let opc = opc - 5;
                    // starts at `0240`
                    const OPC: &[(Opcode, bool)] = &[
                        (Opcode::TWSM, true),
                        (Opcode::TWDSZ, false),
                        (Opcode::TWISZ, false),
                        (Opcode::TWSB, true),
                        (Opcode::TWAD, true),
                        (Opcode::TWLD, true),
                        (Opcode::TWST, true),
                        (Opcode::TWJMP, false),
                        (Opcode::TWJPS, false),
                        // nothing for 0700 - would be a two-word xct
                    ];

                    let (opcode, has_op) = *OPC.get(opc as usize).ok_or(DecodeError::Undefined)?;

                    if change_field {
                        inst.referenced_field = Some(MemoryField::new(field as u8));
                    }

                    inst.opcode = opcode;

                    if has_op {
                        inst.operands[0] = if kj {
                            Operand::K
                        } else {
                            Operand::J
                        };
                        inst.operands[1] = Operand::Absolute(ind, address.0);
                    } else {
                        inst.operands[0] = Operand::Absolute(ind, address.0);
                    }
                }
            },
            0b0010 => {
                // group 1 instructions
                // ```
                // op1 = 0010
                //
                // |      op1      | j | k | shift |  shift count  |
                // |               |acc|acc|  rot  |               |
                // | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10| 11|
                // ```

                let shift = (word.0 & 0o0017) as u8;
                let opc = ((word.0 >> 4) & 0o0003) as u8;
                let kj = ((word.0 >> 6) & 0o0003) as u8;

                let dest = match kj {
                    0b00 => {
                        // opcodes like `0o10xx`
                        // in practice the only instructions here are `0b1000` to `0b1011`
                        let low = (word.0 & 0o0077) as u8;
                        const OPC: &[Opcode] = &[
                            Opcode::MPY,
                            Opcode::DIV,
                            Opcode::RFOV,
                            Opcode::IOFF,
                            Opcode::IONH,
                            Opcode::IONB,
                            Opcode::IONA,
                            Opcode::IONN,
                            Opcode::LJSW,
                            Opcode::LJST,
                        ];
                        inst.opcode = *OPC.get(low as usize).ok_or(DecodeError::Undefined)?;
                        inst.length = words.offset() as u8;

                        return Ok(());
                    },
                    0b01 => Operand::J,
                    0b10 => Operand::K,
                    _ => Operand::JK,
                };

                match opc {
                    0b00 => {
                        // `0b0010xx00xxxx`
                        let opc = shift;
                        if opc == 0o0000 {
                            inst.opcode = Opcode::And;
                            inst.operands[0] = dest;
                        } else if opc == 0o0001 {
                            // Load (R, J) or (S, K)
                            inst.opcode = Opcode::Load;
                            inst.operands[1] = dest;
                            let source = match dest {
                                Operand::J => Operand::R,
                                Operand::K => Operand::S,
                                _ /* JK */ => Operand::RS,
                            };
                            inst.operands[0] = source;
                        } else if opc == 0o0002 {
                            // Load (J, R) or (K, S)
                            inst.opcode = Opcode::Load;
                            inst.operands[0] = dest;
                            let source = match dest {
                                Operand::J => Operand::R,
                                Operand::K => Operand::S,
                                _ /* JK */ => Operand::RS,
                            };
                            inst.operands[1] = source;
                        } else if opc == 0o0003 {
                            // Exchange (J, R) or (K, S)
                            inst.opcode = Opcode::Exchange;
                            inst.operands[0] = dest;
                            let source = match dest {
                                Operand::J => Operand::R,
                                Operand::K => Operand::S,
                                _ /* JK */ => Operand::RS,
                            };
                            inst.operands[1] = source;
                        } else if opc == 0o0004 {
                            // if dest == K, load K from J, else invalid
                            if dest == Operand::K {
                                inst.opcode = Opcode::Load;
                            } else {
                                return Err(DecodeError::Undefined);
                            }
                        } else {
                            return Err(DecodeError::Undefined);
                        }
                    }
                    0b01 => {
                        // `0b0010xx01xxxx`
                        const OPC: &[Option<(Opcode, Option<Operand>)>] = &[
                            Some((Opcode::AddJK, None)),
                            Some((Opcode::SubJK, None)),
                            Some((Opcode::AddR, Some(Operand::R))), // Add (R, J) -> J
                            Some((Opcode::SubR, Some(Operand::R))), // Sub (R, J) -> J
                            Some((Opcode::AddR, Some(Operand::S))), // Add (S, J) -> J
                            Some((Opcode::SubR, Some(Operand::S))), // Sub (S, J) -> J
                            None,
                            None,
                            Some((Opcode::NegAddJK, None)),
                            Some((Opcode::NegSubJK, None)),
                            Some((Opcode::NegAddR, Some(Operand::R))),
                            Some((Opcode::NegSubR, Some(Operand::R))),
                            Some((Opcode::NegAddR, Some(Operand::S))),
                            Some((Opcode::NegSubR, Some(Operand::S))),
                            None,
                            None,
                        ];

                        let (opc, extra_operands) = *OPC.get(shift as usize).and_then(|x| x.as_ref()).ok_or(DecodeError::Undefined)?;
                        inst.opcode = opc;
                        if let Some(extra) = extra_operands {
                            inst.operands[0] = extra;
                            inst.operands[1] = dest;
                        } else {
                            inst.operands[0] = dest;
                        }
                    }
                    0b10 => {
                        inst.opcode = Opcode::Shift;
                        inst.operands[0] = dest;
                        inst.operands[1] = Operand::Literal(shift);
                    }
                    // 0b11
                    _ => {
                        inst.opcode = Opcode::Rotate;
                        inst.operands[0] = dest;
                        inst.operands[1] = Operand::Literal(shift);
                    }
                };
            }
            // octal codes 1400, 1500, 1600, 1700
            0b0011 => {
                // group 2 instructions
                #[allow(non_upper_case_globals)]
                const OPC_Flags: &[Option<(Opcode, Operand)>] = &[
                    Some((Opcode::IDLE, Operand::Nothing)), Some((Opcode::SNZ, Operand::FlagBit)), None, None, None, Some((Opcode::SIZ, Operand::FlagBit)), None, None,
                    Some((Opcode::CLR, Operand::FlagBit)), None, None, None, None, None, None, None,
                    Some((Opcode::CMP, Operand::FlagBit)), None, None, None, None, None, None, None,
                    Some((Opcode::SET, Operand::FlagBit)), None, None, None, None, None, None, None,
                    Some((Opcode::SKPL, Operand::Nothing)), Some((Opcode::SNZ, Operand::OverflowBit)), Some((Opcode::SKIP, Operand::Nothing)), None, None, Some((Opcode::SIZ, Operand::OverflowBit)), None, None,
                    Some((Opcode::CLR, Operand::OverflowBit)), None, None, None, None, None, None, None,
                    Some((Opcode::CMP, Operand::OverflowBit)), None, None, None, None, None, None, None,
                    Some((Opcode::SET, Operand::OverflowBit)), None, None, None, None, None, None, None,
                ];

                #[allow(non_upper_case_globals)]
                const OPC_NotFlags: &[Option<Opcode>] = &[
                    None, Some(Opcode::SNZ), Some(Opcode::SIP), None, Some(Opcode::INC), Some(Opcode::SIZ), Some(Opcode::SIN), None,
                    Some(Opcode::CLR), None, None, None, None, None, None, None,
                    Some(Opcode::CMP), None, None, None, Some(Opcode::NEG), None, None, None,
                    Some(Opcode::SET), None, None, None, None, None, None, None,
                ];

                let jk = (word.0 & 0o0300) >> 6;
                let opc = word.0 & 0o0077;

                if opc == 0o0000 {
                    // idle, pion, piof, or undefined
                    const OPS: &[Result<Opcode, DecodeError>] = &[
                        Ok(Opcode::IDLE),
                        Ok(Opcode::PION),
                        Ok(Opcode::PIOF),
                        Err(DecodeError::Undefined)
                    ];
                    inst.opcode = OPS[jk as usize]?;
                } else {
                    let (opcode, operand) = match jk {
                        0b00 => {
                            *OPC_Flags.get(opc as usize).and_then(|x| x.as_ref()).ok_or(DecodeError::Undefined)?
                        },
                        0b01 => {
                            (*OPC_NotFlags.get(opc as usize).and_then(|x| x.as_ref()).ok_or(DecodeError::Undefined)?, Operand::J)
                        }
                        0b10 => {
                            (*OPC_NotFlags.get(opc as usize).and_then(|x| x.as_ref()).ok_or(DecodeError::Undefined)?, Operand::K)
                        }
                        _ => {
                            (*OPC_NotFlags.get(opc as usize).and_then(|x| x.as_ref()).ok_or(DecodeError::Undefined)?, Operand::JK)
                        }
                    };
                    inst.opcode = opcode;
                    inst.operands[0] = operand;
                }
            }
            // octal code 2000
            0b0100 => {
                // literal instructions, `andf`, `andl`, ``addl`, subl`
                const OPC: &[Opcode] = &[
                    Opcode::ANDF,
                    Opcode::ANDL,
                    Opcode::ADDL,
                    Opcode::SUBL,
                ];

                let opc = (word.0 >> 6) & 0b11;
                let literal = (word.0 & 0o0077) as u8;

                let opc = OPC[opc as usize];
                inst.opcode = opc;
                inst.operands = [
                    Operand::Literal(literal),
                    Operand::Nothing,
                    Operand::Nothing,
                ];
            }
            // octal code 7400+
            0b1111 => {
                // `tif`, `tir`, `trf`, `tis`, ...
                let opc = word.0;
                if opc < 0o7500 {
                    const OPC: &[Option<Opcode>] = &[
                        None, Some(Opcode::TIF), Some(Opcode::TIR), Some(Opcode::TRF), Some(Opcode::TIS), None, None, None,
                        None, Some(Opcode::TOC), Some(Opcode::TOP), Some(Opcode::TCP), Some(Opcode::TOS), None, None, None,
                        None, Some(Opcode::HIS), Some(Opcode::HIR), Some(Opcode::HRF), Some(Opcode::HIS), None, None, None,
                        None, Some(Opcode::HOP), Some(Opcode::HOL), Some(Opcode::HLP), Some(Opcode::HOS), None, None, None,
                    ];
                    let idx = opc - 0o7400;
                    inst.opcode = *OPC.get(idx as usize).and_then(|x| x.as_ref()).ok_or(DecodeError::Undefined)?;
                } else if opc < 0o7600 {
                    return Err(DecodeError::Undefined);
                } else if opc < 0o7700 {
                    inst.opcode = if opc == 0o7601 {
                        Opcode::CSLCT1
                    } else if opc == 0o7602 {
                        Opcode::CSLCT2
                    } else if opc == 0o7604 {
                        Opcode::CSLCT3
                    } else {
                        return Err(DecodeError::Undefined);
                    };
                } else {
                    inst.opcode = if opc == 0o7720 {
                        Opcode::LDREG
                    } else if opc == 0o7721 {
                        Opcode::LDJK
                    } else if opc == 0o7722 {
                        Opcode::RJIB
                    } else {
                        return Err(DecodeError::Undefined);
                    };
                }
            }
            // remaining instructions are keyed entirely on the upper four bits:
            // `smj`, `dsz`, `isz`, `sbj`, `adj`, `ldj`, `stj`, `jmp`, `jps`, `xct`.
            // this set of instructions starts at 0o2400.
            other => {
                const OPC: &[Opcode] = &[
                    Opcode::SMJ,
                    Opcode::DSZ,
                    Opcode::ISZ,
                    Opcode::SBJ,
                    Opcode::ADJ,
                    Opcode::LDJ,
                    Opcode::STJ,
                    Opcode::JMP,
                    Opcode::JPS,
                    Opcode::XCT,
                ];

                let offset = (word.0 & 0o0077) as i8;
                let negative = (word.0 >> 6) & 1;
                let indirect = (word.0 >> 7) & 1;
                let offset = if negative == 1 {
                    -offset
                } else {
                    offset
                };

                let opc = OPC[(other - (0o2400 >> 8)) as usize];
                inst.opcode = opc;
                inst.operands = [
                    Operand::Displacement(indirect == 1, offset),
                    Operand::Nothing,
                    Operand::Nothing,
                ];
            }
        }

        inst.length = words.offset() as u8;
        Ok(())
    }
}
