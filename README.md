# 🏥 Sistema de Gestión de Salud Preventiva

Este proyecto implementa una arquitectura de **Persistencia Políglota**, utilizando diferentes motores de bases de datos para resolver necesidades específicas de un sistema de salud integral.

### 🏗 Arquitectura de Datos
El sistema no depende de una única base de datos, sino que integra varias tecnologías según el tipo de dato:

* **MongoDB (Documental):** Para el almacenamiento de historias clínicas y fichas de pacientes (datos semi-estructurados).
* **Neo4j (Grafos):** Para mapear relaciones complejas entre síntomas, diagnósticos y antecedentes familiares.
* **Cassandra (Columnar):** Para gestionar grandes volúmenes de datos de sensores o registros históricos con alta disponibilidad.
* **SQL (Relacional):** Para la gestión administrativa, facturación y turnos.

### 🛠 Tecnologías Utilizadas
* **Motores NoSQL:** MongoDB, Neo4j, Cassandra.
* **Motores SQL:** MySQL / SQL Server.
* **Lenguajes:** Python (para scripts de integración/ETL).
