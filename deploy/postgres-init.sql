-- One PostgreSQL for the evaluation install, one database per plane.
-- In production each tenant runs its own database in its own network.
CREATE DATABASE central;
CREATE DATABASE tenant;
