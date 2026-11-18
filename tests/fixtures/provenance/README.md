# Signed distribution fixtures

These release files are read as bytes by the offline provenance tests.

- [Sample Project 4.0.0](https://pypi.org/project/sampleproject/4.0.0/)
  provides the source distribution and the
  [PyPI Publish proof](https://pypi.org/integrity/sampleproject/4.0.0/sampleproject-4.0.0.tar.gz/provenance).
- [Build 1.4.4](https://pypi.org/project/build/1.4.4/) provides the wheel.
  The [GitHub SLSA proof](https://github.com/pypa/build/attestations) is the
  DSSE bundle for SHA-256 `8c3f48a6090b39edec1a273d2d57949aaf13723b01e02f9d518396887519f64d`.
- The [Sigstore 4.5.1 wheel](https://pypi.org/project/sigstore/4.5.1/)
  contains the Sigstore Public Good trust root used for both proofs.

The upstream distribution archives retain their licences. The gzip files
preserve the exact producer evidence and Sigstore trust root bytes. The tests
pin each distribution, decompressed evidence bundle, decompressed root and
verified statement digest.
