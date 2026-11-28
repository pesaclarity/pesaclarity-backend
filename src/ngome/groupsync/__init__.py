"""Group sync for shared spaces (decisions 0031, 0033 and 0035).

A relay for the sealed ``.pcshare`` updates the phones of one shared space send each other.
The server stores and passes on ciphertext only: it has no keys, never parses a batch and
merges nothing. Members sign each request with the space member key their phone derives;
no account sign-in is taken here and nothing links a space or a member key to an account.
"""
