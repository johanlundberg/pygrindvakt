//! Shared helpers for the binding: submodule creation, warnings, JSON <-> Python
//! conversion, and the fail-closed plumbing used by the Python protocol adapters.

use pyo3::exceptions::{PyTypeError, PyUserWarning, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyFloat, PyList, PyModule, PyTuple};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Emit a Python `UserWarning` from Rust on a best-effort basis (it never raises
/// back into Rust). Used to flag security downgrades so they cannot be turned on
/// silently.
pub fn warn(py: Python<'_>, message: &str) {
    if let Ok(warnings) = py.import("warnings") {
        let category = py.get_type::<PyUserWarning>();
        let _ = warnings.call_method1("warn", (message, category));
    }
}

/// Create a child submodule, register it under the parent, and insert it into
/// `sys.modules` as `pygrindvakt.<name>` so both `import pygrindvakt.<name>` and
/// attribute access work.
pub fn new_submodule<'py>(
    py: Python<'py>,
    parent: &Bound<'py, PyModule>,
    name: &str,
) -> PyResult<Bound<'py, PyModule>> {
    let child = PyModule::new(py, name)?;
    let qualified = format!("pygrindvakt.{name}");
    child.setattr("__name__", &qualified)?;
    parent.add(name, &child)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item(&qualified, &child)?;
    Ok(child)
}

/// Serialize any `serde::Serialize` value into native Python objects
/// (dict / list / str / int / float / bool / None).
pub fn to_py<'py, T: Serialize + ?Sized>(
    py: Python<'py>,
    value: &T,
) -> PyResult<Bound<'py, PyAny>> {
    // Via `Value`: types holding a `RawValue` (jose-rs `NumericDate`) only
    // serialize correctly through serde_json.
    let value = serde_json::to_value(value).map_err(|e| PyValueError::new_err(e.to_string()))?;
    pythonize::pythonize(py, &value).map_err(PyErr::from)
}

/// serde_json's own nesting limit; deeper input fails there anyway.
const MAX_JSON_DEPTH: usize = 128;

/// JSON has no NaN or infinity and `Value` would silently turn them into
/// `null` (so `{"exp": nan}` would sign as `{"exp": null}`): refuse them.
fn reject_non_finite(obj: &Bound<'_, PyAny>, depth: usize) -> PyResult<()> {
    if depth > MAX_JSON_DEPTH {
        return Err(PyValueError::new_err("value is nested too deeply"));
    }
    if let Ok(f) = obj.cast::<PyFloat>() {
        if !f.value().is_finite() {
            return Err(PyValueError::new_err(
                "non-finite number (NaN or infinity) is not valid JSON",
            ));
        }
    } else if let Ok(d) = obj.cast::<PyDict>() {
        for (_, v) in d.iter() {
            reject_non_finite(&v, depth + 1)?;
        }
    } else if let Ok(l) = obj.cast::<PyList>() {
        for v in l.iter() {
            reject_non_finite(&v, depth + 1)?;
        }
    } else if let Ok(t) = obj.cast::<PyTuple>() {
        for v in t.iter() {
            reject_non_finite(&v, depth + 1)?;
        }
    }
    Ok(())
}

/// Deserialize native Python objects into any `serde::Deserialize` type.
pub fn from_py<T: DeserializeOwned>(obj: &Bound<'_, PyAny>) -> PyResult<T> {
    reject_non_finite(obj, 0)?;
    // Via JSON text: jose-rs `NumericDate` deserializes from a `RawValue`,
    // which only serde_json's own deserializer can supply.
    let value: serde_json::Value = pythonize::depythonize(obj).map_err(PyErr::from)?;
    let text = serde_json::to_string(&value).map_err(|e| PyValueError::new_err(e.to_string()))?;
    // A shape mismatch stays a `TypeError`, as with direct depythonize.
    serde_json::from_str(&text).map_err(|e| {
        if e.is_data() {
            PyTypeError::new_err(e.to_string())
        } else {
            PyValueError::new_err(e.to_string())
        }
    })
}

/// Convert convenience request data into ordered form/query pairs.
///
/// Mappings remain accepted here for the non-protocol convenience fields on
/// `HttpRequestData`. Security-sensitive parser entry points must instead use
/// [`protocol_parameter_pairs`], which rejects mappings.
pub fn parameter_pairs(obj: &Bound<'_, PyAny>, name: &str) -> PyResult<Vec<(String, String)>> {
    if let Ok(mapping) = obj.cast::<PyDict>() {
        return mapping
            .iter()
            .map(|(key, value)| Ok((key.extract()?, value.extract()?)))
            .collect();
    }
    obj.extract::<Vec<(String, String)>>().map_err(|_| {
        PyTypeError::new_err(format!(
            "{name} must be a dict[str, str] or an iterable of (str, str) pairs"
        ))
    })
}

/// Extract ordered protocol parameters without permitting a mapping to erase
/// duplicate names before the Rust validation boundary sees them.
pub fn protocol_parameter_pairs(
    obj: &Bound<'_, PyAny>,
    name: &str,
) -> PyResult<Vec<(String, String)>> {
    if obj.cast::<PyDict>().is_ok() {
        return Err(PyTypeError::new_err(format!(
            "{name} must be an ordered sequence of (str, str) pairs; mappings discard duplicate parameters"
        )));
    }
    obj.extract::<Vec<(String, String)>>().map_err(|_| {
        PyTypeError::new_err(format!(
            "{name} must be an ordered sequence of (str, str) pairs"
        ))
    })
}

/// Log a Python exception raised inside a protocol adapter without propagating
/// it (adapters fail closed). `PyErr::write_unraisable` routes the traceback
/// through `sys.unraisablehook`, so operators can see what went wrong.
pub fn log_unraisable(py: Python<'_>, err: PyErr, obj: &Bound<'_, PyAny>, what: &str) {
    tracing::error!(adapter = what, "python adapter raised; failing closed");
    err.write_unraisable(py, Some(obj));
}

/// Reject objects that do not implement a protocol at construction time rather
/// than at first request.
pub fn require_methods(obj: &Bound<'_, PyAny>, methods: &[&str], proto: &str) -> PyResult<()> {
    for m in methods {
        let ok = obj.getattr(*m).map(|a| a.is_callable()).unwrap_or(false);
        if !ok {
            let tname = obj
                .get_type()
                .name()
                .map(|n| n.to_string())
                .unwrap_or_default();
            return Err(PyTypeError::new_err(format!(
                "{proto}: object of type {tname} has no callable `{m}` method"
            )));
        }
    }
    Ok(())
}
