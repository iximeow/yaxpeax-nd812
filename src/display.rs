use core::fmt;

use crate::{Opcode, Operand, Instruction};

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.opcode {
            Opcode::And => {
                return write!(f, "ad{} {}", self.operands[0], self.operands[1]);
            },
            Opcode::Load => {
                return write!(f, "l{}f{}", self.operands[0], self.operands[1]);
            },
            Opcode::Exchange => {
                return write!(f, "ex{}{}", self.operands[0], self.operands[1]);
            },
            Opcode::AddJK => {
                return write!(f, "ajk {}", self.operands[0]);
            },
            Opcode::SubJK => {
                return write!(f, "sjk {}", self.operands[0]);
            },
            Opcode::AddR => {
                return write!(f, "ad{} {}", self.operands[0], self.operands[1]);
            },
            Opcode::SubR => {
                return write!(f, "sb{} {}", self.operands[0], self.operands[1]);
            },
            Opcode::NegAddJK => {
                return write!(f, "najk {}", self.operands[0]);
            },
            Opcode::NegSubJK => {
                return write!(f, "nsjk {}", self.operands[0]);
            },
            Opcode::NegAddR => {
                return write!(f, "nad{} {}", self.operands[0], self.operands[1]);
            },
            Opcode::NegSubR => {
                return write!(f, "nsb{} {}", self.operands[0], self.operands[1]);
            },
            Opcode::Shift => {
                return write!(f, "sftz {}, {}", self.operands[0], self.operands[1]);
            },
            Opcode::Rotate => {
                return write!(f, "rotd {}, {}", self.operands[0], self.operands[1]);
            },
            _ => {}
        }

        write!(f, "{}", self.opcode)?;
        let mut first_separate_op = 0;
        if [Opcode::TWSM, Opcode::TWSB, Opcode::TWAD, Opcode::TWLD, Opcode::TWST].contains(&self.opcode) {
            write!(f, "{}", self.operands[0])?;
            first_separate_op += 1;
        }

        for i in 0..(self.operand_count() as usize){
            if let Operand::Absolute(true, _) | Operand::Displacement(true, _) = self.operands[i] {
                write!(f, "@")?;
                break;
            }
        }

        if let Some(field) = self.referenced_field.as_ref() {
            write!(f, " field={}", field.num())?;
        }
        for i in first_separate_op..self.operand_count() {
            f.write_str(" ")?;
            format_operand(f, &self.operands[i as usize])?;
            if i + 1 < self.operand_count() {
                f.write_str(",")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Operand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <Operand as fmt::Display>::fmt(self, f)
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::Operand::*;
        match self {
            Nothing => f.write_str("BUG"),
            J => f.write_str("j"),
            K => f.write_str("k"),
            JK => f.write_str("jk"),
            R => f.write_str("r"),
            S => f.write_str("s"),
            RS => f.write_str("rs"),
            OverflowBit => f.write_str("o"),
            FlagBit => f.write_str("f"),
            Displacement(indirect, offset) => {
                if *indirect {
                    f.write_str("(indirect) ")?;
                }
                if *offset < 0 {
                    write!(f, "$-{:#02x}", -offset)
                } else {
                    write!(f, "$+{:#02x}", offset)
                }
            },
            Absolute(indirect, addr) => {
                if *indirect {
                    f.write_str("(indirect) ")?;
                }
                write!(f, "0o{:04o}", addr)
            }
            Literal(value) => {
                write!(f, "${:03x}", value)
            },
        }
    }
}

// mostly the same as the `Display` impl, but does not print `indirect`, since that's supposed to
// be handled by the mnemonic part of the instruction.
fn format_operand(f: &mut fmt::Formatter, op: &Operand) -> fmt::Result {
    use crate::Operand::*;
    match op {
        Nothing => f.write_str(""),
        J => f.write_str("j"),
        K => f.write_str("k"),
        JK => f.write_str("jk"),
        R => f.write_str("r"),
        S => f.write_str("s"),
        RS => f.write_str("rs"),
        OverflowBit => f.write_str("o"),
        FlagBit => f.write_str("f"),
        Displacement(_, offset) => {
            if *offset < 0 {
                write!(f, "$-{:#02x}", -offset)
            } else {
                write!(f, "$+{:#02x}", offset)
            }
        },
        Absolute(_, addr) => {
            write!(f, "0o{:04o}", addr)
        }
        Literal(value) => {
            write!(f, "${:03x}", value)
        },
    }

}

impl fmt::Debug for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <Opcode as fmt::Display>::fmt(self, f)
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Opcode::STOP => {
                f.write_str("stop")
            },
            Opcode::IDLE => {
                f.write_str("idle")
            },
            Opcode::CHSF => {
                f.write_str("chsf")
            },
            Opcode::CSPF => {
                f.write_str("cspf")
            },
            Opcode::CSFM => {
                f.write_str("csfm")
            },
            Opcode::CSET => {
                f.write_str("cset")
            },
            Opcode::CHSR => {
                f.write_str("chsr")
            },
            Opcode::CSNE => {
                f.write_str("csne")
            },
            Opcode::CSTR => {
                f.write_str("cstr")
            },
            Opcode::CSBT => {
                f.write_str("csbt")
            },
            Opcode::CCLF => {
                f.write_str("cclf")
            },
            Opcode::CSRR => {
                f.write_str("csrr")
            },
            Opcode::CRDT => {
                f.write_str("crdt")
            },
            Opcode::CWFM => {
                f.write_str("cwfm")
            },
            Opcode::CSWR => {
                f.write_str("cswr")
            },
            Opcode::CWRT => {
                f.write_str("cwrt")
            },
            Opcode::TWSM => {
                f.write_str("twsm")
            },
            Opcode::TWDSZ => {
                f.write_str("twdsz")
            },
            Opcode::TWISZ => {
                f.write_str("twisz")
            },
            Opcode::TWSB => {
                f.write_str("twsb")
            },
            Opcode::TWAD => {
                f.write_str("twad")
            },
            Opcode::TWLD => {
                f.write_str("twld")
            },
            Opcode::TWST => {
                f.write_str("twst")
            },
            Opcode::TWJMP => {
                f.write_str("twjmp")
            },
            Opcode::TWJPS => {
                f.write_str("twjps")
            },
            Opcode::MPY => {
                f.write_str("mpy")
            },
            Opcode::DIV => {
                f.write_str("div")
            },
            Opcode::RFOV => {
                f.write_str("rfov")
            },
            Opcode::IOFF => {
                f.write_str("ioff")
            },
            Opcode::IONH => {
                f.write_str("ionh")
            },
            Opcode::IONA => {
                f.write_str("iona")
            },
            Opcode::IONB => {
                f.write_str("ionb")
            },
            Opcode::IONN => {
                f.write_str("ionn")
            },
            Opcode::LJSW => {
                f.write_str("ljsw")
            },
            Opcode::LJST => {
                f.write_str("ljst")
            },
            Opcode::And => {
                f.write_str("and")
            },
            Opcode::Load => {
                f.write_str("load")
            }, // load op[0] from [1]
            Opcode::Exchange => {
                f.write_str("exchange")
            }, // exchange op[0], op[1]
            Opcode::AddJK => {
                f.write_str("addjk")
            }, // `op[0] + op[1] to op[2]`
            Opcode::SubJK => {
                f.write_str("subjk")
            }, // `op[0] - op[1] to op[2]`
            Opcode::AddR => {
                f.write_str("addr")
            }, // `op[0] + op[1] to op[2]`
            Opcode::SubR => {
                f.write_str("subr")
            }, // `op[0] - op[1] to op[2]`
            Opcode::NegAddJK => {
                f.write_str("negaddjk")
            }, // `-(op[0] + op[1]) to op[2]`
            Opcode::NegSubJK => {
                f.write_str("negsubjk")
            }, // `(op[1] - op[0]) to op[2]`
            Opcode::NegAddR => {
                f.write_str("negaddr")
            }, // `-(op[0] + op[1]) to op[2]`
            Opcode::NegSubR => {
                f.write_str("negsubr")
            }, // `(op[1] - op[0]) to op[2]`
            Opcode::Shift => {
                f.write_str("shift")
            }, // `j <<= N`, what is N?
            Opcode::Rotate => {
                f.write_str("rotate")
            }, // `j <<= N`, what is N?
            Opcode::SNZ => {
                f.write_str("snz")
            },
            Opcode::SIZ => {
                f.write_str("siz")
            },
            Opcode::CLR => {
                f.write_str("clr")
            },
            Opcode::CMP => {
                f.write_str("cmp")
            },
            Opcode::SET => {
                f.write_str("set")
            },
            Opcode::SKPL => {
                f.write_str("skpl")
            },
            Opcode::PION => {
                f.write_str("pion")
            },
            Opcode::PIOF => {
                f.write_str("piof")
            },
            Opcode::SIP => {
                f.write_str("sip")
            },
            Opcode::INC => {
                f.write_str("inc")
            },
            Opcode::SIN => {
                f.write_str("sin")
            },
            Opcode::NEG => {
                f.write_str("neg")
            },
            Opcode::ANDF => {
                f.write_str("andf")
            },
            Opcode::ANDL => {
                f.write_str("andl")
            },
            Opcode::ADDL => {
                f.write_str("addl")
            },
            Opcode::SUBL => {
                f.write_str("subl")
            },
            Opcode::SMJ => {
                f.write_str("smj")
            },
            Opcode::DSZ => {
                f.write_str("dsz")
            },
            Opcode::ISZ => {
                f.write_str("isz")
            },
            Opcode::SBJ => {
                f.write_str("sbj")
            },
            Opcode::ADJ => {
                f.write_str("adj")
            },
            Opcode::LDJ => {
                f.write_str("ldj")
            },
            Opcode::STJ => {
                f.write_str("stj")
            },
            Opcode::JMP => {
                f.write_str("jmp")
            },
            Opcode::SKIP => {
                f.write_str("skip")
            },
            Opcode::JPS => {
                f.write_str("jps")
            },
            Opcode::XCT => {
                f.write_str("xct")
            },
            Opcode::TIF => {
                f.write_str("tif")
            },
            Opcode::TIR => {
                f.write_str("tir")
            },
            Opcode::TRF => {
                f.write_str("trf")
            },
            Opcode::TIS => {
                f.write_str("tis")
            },
            Opcode::TOC => {
                f.write_str("toc")
            },
            Opcode::TOP => {
                f.write_str("top")
            },
            Opcode::TCP => {
                f.write_str("tcp")
            },
            Opcode::TOS => {
                f.write_str("tos")
            },
            Opcode::HIF => {
                f.write_str("hif")
            },
            Opcode::HIR => {
                f.write_str("hir")
            },
            Opcode::HRF => {
                f.write_str("hrf")
            },
            Opcode::HIS => {
                f.write_str("his")
            },
            Opcode::HOP => {
                f.write_str("hop")
            },
            Opcode::HOL => {
                f.write_str("hol")
            },
            Opcode::HLP => {
                f.write_str("hlp")
            },
            Opcode::HOS => {
                f.write_str("hos")
            },
            Opcode::CSLCT1 => {
                f.write_str("cslct1")
            },
            Opcode::CSLCT2 => {
                f.write_str("cslct2")
            },
            Opcode::CSLCT3 => {
                f.write_str("cslct3")
            },
            Opcode::LDREG => {
                f.write_str("ldreg")
            },
            Opcode::LDJK => {
                f.write_str("ldjk")
            },
            Opcode::RJIB => {
                f.write_str("rjib")
            },
        }
    }
}
