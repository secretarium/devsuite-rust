echo building Rust connector...

cd libs/connector

rm Cargo.lock
rm -rf target
cargo clean
cargo build

cd -

echo building sample Test using Rust connector...

cd test

rm Cargo.lock
rm -rf target
cargo clean
cargo build

cd -

echo done