extern crate oqs;
extern crate serde_json;

#[cfg(feature = "serialize")]
mod serialize {
    use serde_json;
    use oqs::kex::{OqsKex, OqsKexAlg, OqsRandAlg, AliceMsg};

    #[test]
    fn serialize_alice_msg() {
        let kex_alice = OqsKex::new(OqsRandAlg::default(), OqsKexAlg::RlweNewhope)
            .unwrap()
            .alice_0()
            .unwrap();
        let alice_msg = kex_alice.get_alice_msg();

        let alice_msg_json = serde_json::to_value(alice_msg).unwrap();
        let alice_msg_json_array = alice_msg_json.as_array().unwrap();

        assert!(!alice_msg_json_array.is_empty());
        assert_eq!(alice_msg_json_array.len(), alice_msg.data().len());
        for (actual, expected) in alice_msg_json_array.iter().zip(alice_msg.data()) {
            assert_eq!(actual.as_u64().unwrap(), *expected as u64);
        }
    }

    #[test]
    fn serialize_to_string() {
        let kex_alice = OqsKex::new(OqsRandAlg::default(), OqsKexAlg::RlweNewhope)
            .unwrap()
            .alice_0()
            .unwrap();
        let alice_msg = kex_alice.get_alice_msg();

        let json_string = serde_json::to_string(alice_msg).unwrap();

        let deserialized_alice_msg: AliceMsg = serde_json::from_str(&json_string).unwrap();
        assert_eq!(&deserialized_alice_msg, alice_msg);
    }
}
