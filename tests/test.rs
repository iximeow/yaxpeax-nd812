use yaxpeax_arch::Decoder;

fn test_display(data: &[u16], expected: &'static str) {
    let mut reader = yaxpeax_nd812::ND812Reader::of_u16(data);
    match yaxpeax_nd812::InstDecoder::default().decode(&mut reader) {
        Ok(instr) => {
            let displayed = instr.to_string();
            assert_eq!(&displayed, expected);
            assert_eq!(data.len() as u8, instr.len());
        }
        Err(e) => {
            let mut msg = "failed to decode".to_owned();
            if data.len() > 0 {
                msg.push_str(" [");
                msg.push_str(&format!("{:04o}", data[0]));
                for i in 1..data.len() {
                    msg.push_str(", ");
                    msg.push_str(&format!("{:04o}", data[i]));
                }
                msg.push_str("]");
            }
            msg.push_str(": ");
            msg.push_str(&e.to_string());
            panic!("{}", msg);
        }
    }
}

#[test]
fn test_decoder_does_not_panic() {
    for i in 0..0o7777_7777 {
        let low = (i & 0o7777) as u16;
        let high = (i >> 12) as u16;
        let data = &[low, high];
        let mut reader = yaxpeax_nd812::ND812Reader::of_u16(data);
        match yaxpeax_nd812::InstDecoder::default().decode(&mut reader) {
            Ok(instr) => {
                let displayed = instr.to_string();
                assert!(displayed.len() > 0);
            }
            Err(e) => {
                let displayed = e.to_string();
                assert!(displayed.len() > 0);
            }
        }

    }
}
#[test]
fn test_disassembly() {
    test_display(&[0o5464], "stj $+0x34"); // symbol name from IM41-1085
    test_display(&[0o6137], "jmp $-0x1f"); // symbol name from IM41-1085
    test_display(&[0o4417], "adj $+0xf"); // symbol name from IM41-1085
    test_display(&[0o1501], "snz j");
    test_display(&[0o1450], "clr o");
    test_display(&[0o1510], "clr j");
    test_display(&[0o0640, 0o2441], "twjps 0o2441");
    test_display(&[0o0500, 0o2320], "twldj 0o2320");
    test_display(&[0o4446], "adj $+0x26");
    test_display(&[0o5625], "stj@ $+0x15"); // symbol name from IM41-1085
    test_display(&[0o5626], "stj@ $+0x16"); // symbol name from IM41-1085
    test_display(&[0o5004], "ldj $+0x4"); // symbol name from IM41-1085
    test_display(&[0o7170], "xct $-0x38"); // page 8-21 of `IM41-1085`, address `5300`. x14 is a label 0x38 words back..
    test_display(&[0o6554], "jps $-0x2c");
    test_display(&[0o3410], "isz $+0x8"); // symbol name from IM41-1085

    test_display(&[0o1122], "adr j");
    test_display(&[0o1002], "rfov");
    test_display(&[0o1007], "ionn");
    test_display(&[0o1602], "sip k");
    test_display(&[0o7401], "tif");
    test_display(&[0o7722], "rjib");
}
