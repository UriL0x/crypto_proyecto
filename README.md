# Implementación del Algoritmo (Parte B)

## Comandos principales
python -m src.cli init
python -m src.cli encrypt <infile> <outfile>
python -m src.cli decrypt <infile> <outfile>
python -m src.cli test

## Reglas
- Solo se permiten rutas dentro de sandbox/.
- La clave maestra solo existe cifrada dentro de escrow/recovery.enc.
- El programa aborta si detecta intento de acceso fuera de sandbox.

## Ejemplo
python -m src.cli encrypt sandbox/input/a.txt sandbox/output/a.enc
python -m src.cli decrypt sandbox/output/a.enc sandbox/output/a.txt
