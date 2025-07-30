Merkle tree structure:
          root
          /  \
         /    \
        o      o         ← level 1
       / \    / \
      h0  h1 h2  h3       ← level 0
              ↑
            leaf (h2)
            │
            ├── path[0] = h3
            └── path[1] = hash(h0, h1)

selector[0] = false   // leaf is on the left at level 0
selector[1] = true    // goes right at level 1