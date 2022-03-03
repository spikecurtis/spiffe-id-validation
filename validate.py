# This file contains an example algorithm for validating SPIFFE-IDs using only basic string-manipulation
# routines, without any dependencies on URL parsing libraries, regular expressions, etc.  It is written
# in Python, but designed to be easily translated into other languages.
#
# IMPORTANT NOTE: this algorithm and the subroutines `substring`, `character_at` and `len` operate on
# sequences of _characters_, which is not necessarily equivalent to operating on _bytes_, depending on the
# encoding.  (For example, if the string is encoded in UTF-8, the 5th character might not correspond to the 5th
# byte.)  Any sequence of _bytes_ purporting to be a SPIFFE-ID needs to first be decoded into a sequence
# of characters before it can be validated by this method, which means the validator must know the character
# encoding to expect. 

def substring(target, start, end):
    return target[start:end]

def character_at(target, num):
    return target[num]

AUTHORITY_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789.-_"
PATH_SEGMENT_CHARS = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789.-_"


# Returns  valid (bool), authority (string), path (string).  If valid is False, authority and path are set to None.
def validate(spiffe_id):
    # all must begin with spiffe://, which is 9 letters.  So anything under 10 cannot possibly be valid.
    if len(spiffe_id) < 10:
        return False, None, None


    # all must begin with spiffe://
    cursor = 0
    if substring(spiffe_id, cursor, 9) != "spiffe://":
        return False, None, None

    # compute authority, checking valid letters until / or end of string.
    cursor = 9
    while cursor < len(spiffe_id):
        c = character_at(spiffe_id, cursor)
        if c == "/":
            break
        # Note here that since valid letters does not include @ or :,
        # this ensures that userinfo and port are not set in the authority 
        if c not in AUTHORITY_CHARS:
            return False, None, None
        cursor += 1
    authority = substring(spiffe_id, 9, cursor)
    path = substring(spiffe_id, cursor, len(spiffe_id))

    # Authority must not be empty.
    if len(authority) == 0:
        return False, None, None

    # A SPIFFE-ID that includes only the authority (empty-path) is valid.
    if len(path) == 0:
        return True, authority, path

    # per RFC3986, since the authority is not empty, the path must be empty or 
    # begin with a slash.  In order to exit the while loop above, we must either
    # encounter a slash, or the end of the string (and thus the path is empty).
    # Since we check above for an empty path, we know the path begins with a slash
    # as required.

    # We now check the path, character by character, and segment by segment.
    cursor += 1
    segment_start = cursor
    while cursor < len(spiffe_id):
        c = character_at(spiffe_id, cursor)
        if c == "/":
            segment = substring(spiffe_id, segment_start, cursor)
            # Segments cannot be empty, or contain relative path elements
            if segment in ["", ".", ".."]:
                return False, None, None
            cursor += 1
            segment_start = cursor
            continue
        if c not in PATH_SEGMENT_CHARS:
            return False, None, None
        cursor += 1
    
    # above code checks all characters and any path segments that are delimited
    # by a /.  The final path segment is not delimited by a /, so we check it
    # here.  Note that checking against "" also enforces that the path does not
    # end in a trailing /.
    segment = substring(spiffe_id, segment_start, cursor)
    if segment in ["", ".", ".."]:
                return False, None, None


    return True, authority, path

if __name__ == "__main__":
    examples = [
        ("", (False, None, None)),
        ("spiffe://", (False, None, None)),
        ("spiffe:///", (False, None, None)),
        ("spiffe://Foo/bar", (False, None, None)),
        ("spiffe://foo:bar", (False, None, None)),
        ("spiffe://foo/bar", (True, "foo", "/bar")),
        ("spiffe://foö/bar", (False, None, None)),
        ("spiffe://foo/bär", (False, None, None)),
        ("spiffe://foo/", (False, None, None)),
        ("spiffe://foo", (True, "foo", "")),
        ("spiffe://foo.bar/Baz/buZ", (True, "foo.bar", "/Baz/buZ")), 
        ("spiffe://foo.bar/Baz/buZ/", (False, None, None)), 
        ("spiffe://foo.bar//buZ/", (False, None, None)), 
        ("spiffe://foo.bar/../buZ/", (False, None, None)), 
        ("spiffe://foo.bar/..Baz/.buZ", (True, "foo.bar", "/..Baz/.buZ")), 
        ("spiffe://foo.bar/buZ/%2d", (False, None, None)), 
        ("Spiffe://foo.bar/Baz/buZ", (False, None, None)), 
        ("spiffe://domain.test/path/validate?query=1", (False, None, None)),
        ("spiffe://domain.test/path/validate?#fragment-1", (False, None, None)),
        ("spiffe://domain.test:8080/path/validate", (False, None, None)),
        ("spiffe://user:password@test.org/path/validate", (False, None, None)),
    ]
    for e, r in examples:
        v = validate(e)
        print(repr(e), v, "" if v == r else "FAILED!")
