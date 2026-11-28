"""Group sync for shared spaces (decisions 0031, 0033 and 0035).

A relay for the sealed ``.pcshare`` updates the phones of one shared space send each other.
The server stores and passes on what the phones send and never opens it: it has no keys,
never parses a batch and merges nothing. Members sign each request with the space member key
their phone derives; no account sign-in is taken here and nothing links a space or a member
key to an account.

What it stores is not all ciphertext. The entries in a batch are sealed, but the app puts
the file's true length in front of it, and a ``.pcshare`` file opens with a header in clear:
random ids of the space, the file, the sender and the recipient, which space key sealed it,
and the phone's time.
"""
