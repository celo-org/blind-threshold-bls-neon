use neon::prelude::*;

use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};
use anyhow::Error;

use threshold_bls::schemes::bls12_377::{G2Scheme as SigScheme};
use threshold_bls::{
    poly::{Idx as Index, Poly},
    sig::{
        BlindScheme, BlindThresholdScheme, Scheme, Share, SignatureScheme, ThresholdScheme, Token,
    },
};

pub type PublicKey = <SigScheme as Scheme>::Public;
pub type PrivateKey = <SigScheme as Scheme>::Private;

pub const VEC_LENGTH: usize = 8;
pub const SIGNATURE_LEN: usize = 48;
pub const PARTIAL_SIG_LENGTH: usize =
    VEC_LENGTH + SIGNATURE_LEN + std::mem::size_of::<Index>();

fn get_rng(digest: &[u8]) -> impl RngCore {
    let seed = from_slice(digest);
    ChaChaRng::from_seed(seed)
}

fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

pub fn blind(mut cx: FunctionContext) -> JsResult<JsObject> {
  let message = get_buffer_argument(&mut cx, 0);
  let seed = get_buffer_argument(&mut cx, 1);

  let mut rng = get_rng(&seed);
  let (blinding_factor, blinded_message) = SigScheme::blind_msg(&message, &mut rng);

  let blinded_message_ret = JsObject::new(&mut cx);
  let blinding_factor_buffer = serialize_to_js_buffer(&mut cx, &blinding_factor).unwrap();
  blinded_message_ret.set(&mut cx, "blindingFactor", blinding_factor_buffer);
  let blinded_message_buffer = buffer_to_js_buffer(&mut cx, &blinded_message).unwrap();
  blinded_message_ret.set(&mut cx, "message", blinded_message_buffer);
  Ok(blinded_message_ret)
}

pub fn unblind(mut cx: FunctionContext) -> JsResult<JsBuffer> {
  let blinded_signature = get_buffer_argument(&mut cx, 0);
  let blinding_factor_buf = get_buffer_argument(&mut cx, 1);

  let blinding_factor: Token<PrivateKey> =
      bincode::deserialize(&blinding_factor_buf).unwrap();

  Ok(buffer_to_js_buffer(&mut cx, &SigScheme::unblind_sig(&blinding_factor, &blinded_signature).unwrap()).unwrap())
}

pub fn partial_sign_blinded_message(mut cx: FunctionContext) -> JsResult<JsBuffer> {
  let share_buf = get_buffer_argument(&mut cx, 0);
  let message = get_buffer_argument(&mut cx, 1);

  let share: Share<PrivateKey> = bincode::deserialize(&share_buf).unwrap();
  Ok(buffer_to_js_buffer(&mut cx, &SigScheme::sign_blind_partial(&share, &message).unwrap()).unwrap())
}

pub fn partial_verify_blind_signature(mut cx: FunctionContext) -> JsResult<JsUndefined> {
  let polynomial_buf = get_buffer_argument(&mut cx, 0);
  let blinded_message = get_buffer_argument(&mut cx, 1);
  let sig = get_buffer_argument(&mut cx, 2);
  let polynomial: Poly<PublicKey> = bincode::deserialize(&polynomial_buf).unwrap();

  SigScheme::verify_blind_partial(&polynomial, &blinded_message, &sig).unwrap();
  Ok(cx.undefined())
}

fn get_int_argument<'a>(cx: &mut FunctionContext<'a>, index: i32) -> usize {
  cx.argument::<JsNumber>(index).expect("should have gotten argument").value() as usize
}

fn get_buffer_argument<'a>(cx: &mut FunctionContext<'a>, index: i32) -> Vec<u8> {
  let b: Handle<JsBuffer> = cx.argument(index).expect("should have gotten argument");
  cx.borrow(&b, |data| data.as_slice::<u8>().to_vec())
}

fn serialize_to_js_buffer<'a, T: serde::Serialize>(cx: &mut FunctionContext<'a>, obj: &T) -> Result<Handle<'a, JsBuffer>, Error> {
  let bytes = bincode::serialize(obj)?;
  buffer_to_js_buffer(cx, &bytes)
}

fn buffer_to_js_buffer<'a>(cx: &mut FunctionContext<'a>, bytes: &[u8]) -> Result<Handle<'a, JsBuffer>, Error> {
  let mut buffer = JsBuffer::new(cx, bytes.len() as u32).expect("should have allocated");
  cx.borrow_mut(&mut buffer, |data| {
      let mut slice = data.as_mut_slice::<u8>();
      slice.copy_from_slice(&bytes);
  });

  Ok(buffer)
}

fn combine(mut cx: FunctionContext) -> JsResult<JsBuffer> {
  let threshold = get_int_argument(&mut cx, 0);
  let signatures = get_buffer_argument(&mut cx, 1);
  // break the flattened vector to a Vec<Vec<u8>> where each element is a serialized signature
  let sigs = signatures
      .chunks(PARTIAL_SIG_LENGTH)
      .map(|chunk| chunk.to_vec())
      .collect::<Vec<Vec<u8>>>();

  Ok(buffer_to_js_buffer(&mut cx, &SigScheme::aggregate(threshold, &sigs).unwrap()).unwrap())
}

fn verify(mut cx: FunctionContext) -> JsResult<JsUndefined> {
  let public_key_buf = get_buffer_argument(&mut cx, 0);
  let message = get_buffer_argument(&mut cx, 1);
  let signature = get_buffer_argument(&mut cx, 2);

  let public_key: PublicKey = bincode::deserialize(&public_key_buf).unwrap();
  SigScheme::verify(&public_key, &message, &signature);

  Ok(cx.undefined())
}

register_module!(mut m, {
  m.export_function("blind", blind).unwrap();
  m.export_function("unblind", unblind).unwrap();
  m.export_function("partialSignBlindedMessage", partial_sign_blinded_message).unwrap();
  m.export_function("partialVerifyBlindSignature", partial_verify_blind_signature).unwrap();
  m.export_function("combine", combine)
});
