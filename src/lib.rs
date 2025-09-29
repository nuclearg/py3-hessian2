use pyo3::prelude::*;

/// A Python module implemented in Rust.
#[pymodule]
fn py3_hessian2_rsimpl(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(helloworld, m)?)?;
    Ok(())
}

#[pyfunction]
fn helloworld() -> Vec<u8> {
    b"Hello, World from Rust!".to_vec()
}