CREATE TABLE holdings(
    id INTEGER,
    user_id INTEGER,
    transaction_time DEFAULT CURRENT_TIMESTAMP NOT NULL,
    firm TEXT NOT NULL,
    symbol TEXT NOT NULL,
    shares NUMERIC NOT NULL,
    price NUMERIC NOT NULL,
    transaction_type TEXT NOT NULL,
    PRIMARY KEY(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
);