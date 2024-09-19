CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10, 2) NOT NULL
);

INSERT INTO products (name, price) VALUES
    ('Laptop', 999.99),
    ('Smartphone', 599.99),
    ('Headphones', 149.99);