import hessian2

def test_helloworld():
    result = hessian2.helloworld()
    expected = b"Hello, World from Rust!"
    assert result == expected, f"Expected {expected!r}, but got {result!r}"
    print("Test passed!")

if __name__ == "__main__":
    test_helloworld()