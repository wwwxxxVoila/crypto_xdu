def is_pkcs7_padded(binary_data):
    """Returns whether the data is PKCS 7 padded."""

    # Take what we expect to be the padding
    padding = binary_data[-binary_data[-1]:]

    # Check that all the bytes in the range indicated by the padding are equal to the padding value itself
    return all(padding[b] == len(padding) for b in range(0, len(padding)))


def main():
    """I had implemented the is_pkcs_padded method before, so I will just reuse it here."""
    assert is_pkcs7_padded(b'ICE ICE BABY\x04\x04\x04\x04') is True
    assert is_pkcs7_padded(b'ICE ICE BABY\x05\x05\x05\x05') is False
    assert is_pkcs7_padded(b'ICE ICE BABY\x01\x02\x03\x04') is False
    assert is_pkcs7_padded(b'ICE ICE BABY') is False
    print("恭喜喵 断言全部通过")

if __name__ == '__main__':
    main()