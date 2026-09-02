-- ══════════════════════════════════════════════════════════════════
--  TrendSphere — Fix: Trend Predictions Table
--  Run this ONE TIME in pgAdmin to fix the trend predictions system
-- ══════════════════════════════════════════════════════════════════

-- 1. Add missing columns (safe — IF NOT EXISTS)
ALTER TABLE trend_predictions ADD COLUMN IF NOT EXISTS view_velocity    DECIMAL(8,4) DEFAULT 0;
ALTER TABLE trend_predictions ADD COLUMN IF NOT EXISTS search_momentum  DECIMAL(8,4) DEFAULT 0;
ALTER TABLE trend_predictions ADD COLUMN IF NOT EXISTS wishlist_signal  DECIMAL(8,4) DEFAULT 0;
ALTER TABLE trend_predictions ADD COLUMN IF NOT EXISTS cart_intent      DECIMAL(8,4) DEFAULT 0;
ALTER TABLE trend_predictions ADD COLUMN IF NOT EXISTS anomaly          BOOLEAN DEFAULT FALSE;
ALTER TABLE trend_predictions ADD COLUMN IF NOT EXISTS forecast_7d      DECIMAL(8,4) DEFAULT 0;
ALTER TABLE trend_predictions ADD COLUMN IF NOT EXISTS confidence       DECIMAL(5,4) DEFAULT 0;
ALTER TABLE trend_predictions ADD COLUMN IF NOT EXISTS predicted_at     TIMESTAMP DEFAULT NOW();

-- 2. Add UNIQUE constraint on product_id so ON CONFLICT works
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'trend_predictions_product_id_key'
    ) THEN
        ALTER TABLE trend_predictions
            ADD CONSTRAINT trend_predictions_product_id_key UNIQUE (product_id);
    END IF;
END $$;

-- 3. Fix the broken trigger that caused the ref_id error
DROP TRIGGER  IF EXISTS trg_notify_new_order ON orders;
DROP FUNCTION IF EXISTS notify_new_order();

-- 4. Recreate trigger without ref_id
CREATE OR REPLACE FUNCTION notify_new_order()
RETURNS TRIGGER AS $$
BEGIN
    BEGIN
        INSERT INTO admin_notifications (type, title, message, is_read, created_at)
        VALUES (
            'new_order',
            'New Order: ' || NEW.order_code,
            'Order ' || NEW.order_code || ' placed for ₹' || NEW.total_amount,
            FALSE,
            NOW()
        );
    EXCEPTION WHEN OTHERS THEN
        NULL; -- Never block an order insert due to notification failure
    END;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_notify_new_order
    AFTER INSERT ON orders
    FOR EACH ROW EXECUTE FUNCTION notify_new_order();

-- 5. Also fix low-stock trigger if it has ref_id issue
DROP TRIGGER  IF EXISTS trg_low_stock ON products;
DROP FUNCTION IF EXISTS notify_low_stock();

CREATE OR REPLACE FUNCTION notify_low_stock()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.stock <= 5 AND OLD.stock > 5 THEN
        BEGIN
            INSERT INTO admin_notifications (type, title, message, is_read, created_at)
            VALUES (
                'low_stock',
                '⚠️ Low Stock: ' || NEW.name,
                'Product "' || NEW.name || '" has only ' || NEW.stock || ' units left.',
                FALSE,
                NOW()
            );
        EXCEPTION WHEN OTHERS THEN
            NULL;
        END;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_low_stock
    AFTER UPDATE OF stock ON products
    FOR EACH ROW EXECUTE FUNCTION notify_low_stock();

-- 6. Verify
SELECT
    'trend_predictions columns' AS check_name,
    string_agg(column_name, ', ' ORDER BY ordinal_position) AS columns
FROM information_schema.columns
WHERE table_name = 'trend_predictions';

SELECT 'Fix applied successfully ✅' AS status;
