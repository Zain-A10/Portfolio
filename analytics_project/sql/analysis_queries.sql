/* =========================================================
   POINT-OF-SALE FRAUD ANALYTICS PROJECT
   Author: Zain Arif
   ========================================================= */


/* =========================================================
   1. OVERALL FRAUD RATE
   ========================================================= */

SELECT
    COUNT(*) AS total_transactions,
    SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END) AS fraud_transactions,
    ROUND(
        100.0 * SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END)
        / COUNT(*),
        2
    ) AS fraud_rate_percent
FROM transactions;


/* =========================================================
   2. FRAUD RATE BY MERCHANT CATEGORY
   ========================================================= */

SELECT
    merchant_category,
    COUNT(*) AS total_transactions,
    SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END) AS fraud_transactions,
    ROUND(
        100.0 * SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END)
        / COUNT(*),
        2
    ) AS fraud_rate_percent
FROM transactions
GROUP BY merchant_category
ORDER BY fraud_rate_percent DESC;


/* =========================================================
   3. TOP MERCHANTS BY FRAUD LOSS
   ========================================================= */

SELECT
    merchant_id,
    SUM(
        CASE
            WHEN is_fraud = TRUE
            THEN transaction_amount
            ELSE 0
        END
    ) AS fraud_loss
FROM transactions
GROUP BY merchant_id
ORDER BY fraud_loss DESC
LIMIT 10;


/* =========================================================
   4. FRAUD RATE BY STATE
   ========================================================= */

SELECT
    state,
    COUNT(*) AS transactions,
    SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END) AS fraud_count,
    ROUND(
        100.0 * SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END)
        / COUNT(*),
        2
    ) AS fraud_rate
FROM transactions
GROUP BY state
ORDER BY fraud_rate DESC;


/* =========================================================
   5. FRAUD RATE BY PAYMENT METHOD
   ========================================================= */

SELECT
    payment_method,
    COUNT(*) AS transactions,
    SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END) AS fraud_count,
    ROUND(
        100.0 * SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END)
        / COUNT(*),
        2
    ) AS fraud_rate
FROM transactions
GROUP BY payment_method
ORDER BY fraud_rate DESC;


/* =========================================================
   6. HIGH-RISK CUSTOMERS
   ========================================================= */

SELECT
    customer_id,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN is_fraud = TRUE
            THEN 1
            ELSE 0
        END
    ) AS fraud_events,
    ROUND(SUM(transaction_amount), 2) AS total_spend
FROM transactions
GROUP BY customer_id
HAVING SUM(
        CASE
            WHEN is_fraud = TRUE
            THEN 1
            ELSE 0
        END
    ) >= 2
ORDER BY fraud_events DESC;


/* =========================================================
   7. FRAUD LOSS BY MERCHANT CATEGORY
   ========================================================= */

SELECT
    merchant_category,
    COUNT(*) AS transactions,
    SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END) AS fraud_transactions,
    ROUND(
        SUM(
            CASE
                WHEN is_fraud = TRUE
                THEN transaction_amount
                ELSE 0
            END
        ),
        2
    ) AS fraud_loss
FROM transactions
GROUP BY merchant_category
ORDER BY fraud_loss DESC;


/* =========================================================
   8. MERCHANT CATEGORY FRAUD LOSS RANKING
   WINDOW FUNCTION
   ========================================================= */

SELECT
    merchant_category,
    COUNT(*) AS total_transactions,
    SUM(
        CASE
            WHEN is_fraud = TRUE
            THEN transaction_amount
            ELSE 0
        END
    ) AS fraud_loss,
    RANK() OVER (
        ORDER BY
        SUM(
            CASE
                WHEN is_fraud = TRUE
                THEN transaction_amount
                ELSE 0
            END
        ) DESC
    ) AS fraud_loss_rank
FROM transactions
GROUP BY merchant_category;


/* =========================================================
   9. HIGH-RISK MERCHANTS USING CTE
   ========================================================= */

WITH merchant_fraud AS (
    SELECT
        merchant_id,
        COUNT(*) AS total_transactions,
        SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END) AS fraud_transactions,
        ROUND(
            100.0 *
            SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END)
            / COUNT(*),
            2
        ) AS fraud_rate
    FROM transactions
    GROUP BY merchant_id
)

SELECT *
FROM merchant_fraud
WHERE fraud_rate >= 5
ORDER BY fraud_rate DESC;


/* =========================================================
   10. MONTHLY FRAUD TREND
   ========================================================= */

SELECT
    DATE_TRUNC('month', transaction_date) AS month,
    COUNT(*) AS total_transactions,
    SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END) AS fraud_transactions,
    ROUND(
        100.0 *
        SUM(CASE WHEN is_fraud = TRUE THEN 1 ELSE 0 END)
        / COUNT(*),
        2
    ) AS fraud_rate
FROM transactions
GROUP BY month
ORDER BY month;


/* =========================================================
   11. HIGH-VALUE FRAUD TRANSACTIONS
   ========================================================= */

SELECT *
FROM transactions
WHERE is_fraud = TRUE
AND transaction_amount >= 1000
ORDER BY transaction_amount DESC;


/* =========================================================
   12. FRAUD TYPE BREAKDOWN
   ========================================================= */

SELECT
    fraud_type,
    COUNT(*) AS fraud_count,
    ROUND(SUM(transaction_amount), 2) AS total_amount
FROM transactions
WHERE is_fraud = TRUE
GROUP BY fraud_type
ORDER BY fraud_count DESC;