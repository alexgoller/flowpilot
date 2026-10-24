//! The flow upload message: the protobuf (proto2) body FlowPilot gzips and POSTs to
//! `/api/v2/orgs/<org>/traffic_data/flowlink`. An `UploadBatch` holds the window's `UploadRecord`s.
//! Field numbers, types and labels are the wire format the PCE accepts for flow uploads.

#[derive(Clone, PartialEq, prost::Message)]
pub struct UploadRecord {
    #[prost(int64, required, tag = "1", default = "-1")]
    pub timestamp: i64,
    #[prost(bytes = "vec", required, tag = "2")]
    pub src_ip: Vec<u8>,
    #[prost(bytes = "vec", required, tag = "3")]
    pub dst_ip: Vec<u8>,
    #[prost(int32, required, tag = "4", default = "-1")]
    pub dst_port: i32,
    #[prost(int32, required, tag = "5", default = "-1")]
    pub proto: i32,
    #[prost(int32, required, tag = "6", default = "-1")]
    pub count: i32,
    #[prost(int32, optional, tag = "7", default = "-1")]
    pub icmp_type: Option<i32>,
    #[prost(int32, optional, tag = "8", default = "-1")]
    pub icmp_code: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "9")]
    pub src_mac: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "10")]
    pub dst_mac: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "11")]
    pub device_addr: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "12")]
    pub src_mask_bits: Option<i32>,
    #[prost(int32, optional, tag = "13")]
    pub dst_mask_bits: Option<i32>,
    #[prost(uint64, optional, tag = "14")]
    pub octets: Option<u64>,
    #[prost(int64, optional, tag = "15")]
    pub dst_dbi: Option<i64>,
    #[prost(int64, optional, tag = "16")]
    pub dst_dbo: Option<i64>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct UploadBatch {
    #[prost(int32, required, tag = "1", default = "-1")]
    pub aggregation_seconds: i32,
    #[prost(int32, optional, tag = "2")]
    pub org_id: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub installation_id: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub pce_host: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub instance_id: Option<Vec<u8>>,
    #[prost(message, repeated, tag = "10")]
    pub flows: Vec<UploadRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn required_fields_are_always_encoded() {
        // Required fields are always written, even when they hold zero, as the PCE expects.
        let rec = UploadRecord { timestamp: 0, src_ip: vec![10, 0, 0, 1], dst_ip: vec![10, 0, 0, 2], ..Default::default() };
        let td = UploadBatch { aggregation_seconds: 0, instance_id: Some(b"id".to_vec()), flows: vec![rec], ..Default::default() };
        let bytes = td.encode_to_vec();
        // aggregation_seconds=0 (08 00), instance_id (2a 02 'i' 'd'), flows (52 len ...)
        assert_eq!(&bytes[..6], &[0x08, 0x00, 0x2a, 0x02, b'i', b'd']);
        let back = UploadBatch::decode(bytes.as_slice()).unwrap();
        assert_eq!(back, td);
    }
}
