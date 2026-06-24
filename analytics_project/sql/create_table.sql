/* =========================================================
   POINT-OF-SALE FRAUD ANALYTICS PROJECT
   Database Schema
   ========================================================= */

DROP TABLE IF EXISTS transactions;

CREATE TABLE transactions (
    transaction_id SERIAL PRIMARY KEY,
    customer_id INT NOT NULL,
    merchant_id INT NOT NULL,
    merchant_category VARCHAR(50) NOT NULL,
    transaction_amount DECIMAL(10,2) NOT NULL,
    transaction_date DATE NOT NULL,
    transaction_time TIME NOT NULL,
    state VARCHAR(30) NOT NULL,
    payment_method VARCHAR(20) NOT NULL,
    transaction_status VARCHAR(20) NOT NULL,
    is_fraud BOOLEAN NOT NULL,
    fraud_type VARCHAR(50)
);