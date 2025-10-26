# Validation Challenges

Esta carpeta contiene challenges reales para validar el sistema CTF solver.

## Estructura

- `rsa/` - Challenges de RSA
- `classical/` - Cifrados clásicos (Caesar, Vigenère, etc.)
- `xor/` - Challenges de XOR
- `encoding/` - Challenges de encoding (Base64, hex, etc.)
- `hash/` - Challenges de hash cracking
- `mixed/` - Challenges mixtos o complejos

## Uso

```bash
# Resolver un challenge individual
python solve.py validation_challenges/rsa/small_e.py

# Resolver todos los challenges
python solve_batch.py validation_challenges/

# Resolver solo RSA challenges
python solve_batch.py validation_challenges/rsa/
```

## Target Success Rate

- **Known challenge types**: 90-100%
- **Similar challenges**: 80-90%
- **New challenge types**: 60-70%