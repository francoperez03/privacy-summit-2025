# Challenge: Circuito de Pago Privado (Stage 3)

Diseña un sistema de transferencias privadas donde puedas enviar dinero sin revelar cuánto ni a quién.

---

## El Problema

Quiero enviar **70 tokens** a mi amiga. Tengo una **nota** con **100 tokens**.

¿Cómo pruebo que:
1. Soy dueño de esa nota
2. Tiene suficiente saldo
3. Creo dos nuevas notas: **70 para ella, 30 de cambio para mí**
4. No estoy haciendo trampa (doble gasto, inflación, etc.)

...sin revelar los montos ni las identidades?

---

## Conceptos Básicos

### Una "Nota" (Note)

```
nota = H(valor, owner_pk, salt)
```

- Es como un billete privado
- Solo quien conoce `(valor, owner_pk, salt)` puede gastarla
- El hash se publica en un árbol Merkle (commitment público)

### Nullifier (Prevención de Doble Gasto)

```
nullifier_hash = H(nsk, note_hash)
```

- `nsk` = nullifier secret key (clave secreta del dueño)
- Solo el dueño puede calcular el `nullifier_hash` correcto
- Se publica cuando gastas la nota
- Si alguien intenta gastar la misma nota → mismo `nullifier_hash` → rechazo

---

## Tu Desafío (Pregunta por Pregunta)

### 🔍 Pregunta 1: ¿Cómo pruebo que soy dueño de la nota?

**Pista:** La nota es `note_hash = H(valor, owner_pk, salt)` y existe en el árbol Merkle.

**¿Qué necesitas verificar?**
1. Recalcular el hash de la nota con los valores privados
2. Probar que ese hash está en el árbol (Merkle proof)
3. Probar que conoces la clave secreta correspondiente a `owner_pk`

**Escribe las restricciones:**
```rust
// Tu código aquí
let note_hash = ...
let root_calc = compute_root(note_hash, index, path);
assert(root_calc == merkle_root);
assert(owner_pk == ...);
```

---

### 🔍 Pregunta 2: ¿Cómo evito el doble gasto?

**Pista:** Usa un `nullifier_hash` que sea único por nota.

**¿Qué necesitas?**
- Calcular `nullifier_hash = H(nsk, note_hash)`
- Hacerlo público (para que el verifier lo registre)
- Verificar que el cálculo es correcto

**Escribe la restricción:**
```rust
let nullifier_calc = ...
assert(nullifier_calc == nullifier_hash);
```

**Pregunta adicional:** ¿Por qué solo el dueño puede generar el `nullifier_hash` correcto?

---

### 🔍 Pregunta 3: ¿Cómo creo las dos notas de salida?

Necesitas crear:
- **Nota para el destinatario:** `note_hash_pago = H(valor_pago, destinatario_pk, salt_pago)`
- **Nota de cambio:** `note_hash_cambio = H(valor_cambio, owner_pk, salt_cambio)`

**¿Qué necesitas verificar?**
```rust
let note_pago_calc = ...
assert(note_pago_calc == note_hash_pago);

let note_cambio_calc = ...
assert(note_cambio_calc == note_hash_cambio);
```

**Pregunta adicional:** ¿Por qué estos hashes deben ser públicos?

---

### 🔍 Pregunta 4: ¿Cómo garantizo que no estoy creando dinero de la nada?

**Ley de conservación:** Lo que entra = lo que sale

**Escribe la restricción:**
```rust
assert(valor_in == ...);
```

---

### 🔍 Pregunta 5: ¿Qué es público y qué es privado?

**Completa esta tabla:**

| Dato                 | ¿Público o Privado? | ¿Por qué?                                    |
|----------------------|---------------------|----------------------------------------------|
| `valor_in`           | ?                   | ?                                            |
| `valor_pago`         | ?                   | ?                                            |
| `owner_pk`           | ?                   | ?                                            |
| `destinatario_pk`    | ?                   | ?                                            |
| `merkle_root`        | ?                   | ?                                            |
| `nullifier_hash`     | ?                   | ?                                            |
| `note_hash_pago`     | ?                   | ?                                            |
| `note_hash_cambio`   | ?                   | ?                                            |
| `nsk`                | ?                   | ?                                            |

---

### 🔍 Pregunta 6: ¿Qué ataques debo prevenir?

Por cada ataque, responde: **¿Dónde falla en mi circuito?**

1. **Doble gasto:** Gasto la misma nota dos veces
   - Falla en: `______________________________`

2. **Inflación:** `valor_pago + valor_cambio > valor_in`
   - Falla en: `______________________________`

3. **Gastar nota ajena:** Uso una nota que no es mía
   - Falla en: `______________________________`

4. **Merkle proof falso:** Invento un camino en el árbol
   - Falla en: `______________________________`

5. **Cambiar destinatario:** Pruebo con una PK, publico otra
   - Falla en: `______________________________`

6. **Nullifier falso:** Genero un nullifier inventado
   - Falla en: `______________________________`

---

## Responsabilidades del Verifier (Off-Chain)

El verifier debe:
1. Mantener el árbol Merkle con todas las notas
2. Llevar un set de `nullifier_hash` ya usados
3. Rechazar si `nullifier_hash` ya existe (doble gasto)
4. Añadir `note_hash_pago` y `note_hash_cambio` al árbol después de verificar

---

## Bonus: Preguntas para Reflexionar

- ¿Se puede saber quién pagó a quién?
- ¿Se puede saber cuánto se pagó?
- ¿Qué pasa si uso un `merkle_root` viejo?
- ¿Puedo enviar todo mi dinero (cambio = 0)?
- ¿Qué pasa si `destinatario_pk == owner_pk`? ¿Es válido?

---

**¡Éxito con el challenge!** 🚀

Este es el circuito más completo del workshop. Tómate tu tiempo, completa las preguntas paso a paso, y construye un sistema de pagos privados seguro.
