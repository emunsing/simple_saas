-- ============================================================
-- 1. Drop all triggers on auth.users and all public tables
-- ============================================================

DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT trigger_name, event_object_schema, event_object_table
    FROM information_schema.triggers
    WHERE (
      -- All triggers on public tables are ours
      event_object_schema = 'public'
      OR (
        -- On auth tables, only drop triggers calling our functions
        event_object_schema = 'auth'
        AND action_statement LIKE '%public.%'
      )
    )
    GROUP BY trigger_name, event_object_schema, event_object_table
  LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I.%I',
      r.trigger_name, r.event_object_schema, r.event_object_table);
  END LOOP;
END $$;

-- ============================================================
-- 2. Drop all RLS policies on all public tables
-- ============================================================
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
      r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

-- ============================================================
-- 3. Drop all functions in public schema
-- ============================================================
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS func_signature
    FROM pg_proc p
    JOIN pg_namespace n ON p.pronamespace = n.oid
    WHERE n.nspname = 'public'
  LOOP
    EXECUTE format('DROP FUNCTION IF EXISTS %s CASCADE', r.func_signature);
  END LOOP;
END $$;

-- ============================================================
-- 4. Drop all tables in public schema (CASCADE handles FKs)
-- ============================================================
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'public'
  LOOP
    EXECUTE format('DROP TABLE IF EXISTS public.%I CASCADE', r.tablename);
  END LOOP;
END $$;

-- ============================================================
-- 5. Drop all custom types in public schema
-- ============================================================
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT t.typname
    FROM pg_type t
    JOIN pg_namespace n ON t.typnamespace = n.oid
    WHERE n.nspname = 'public'
      AND t.typtype = 'e'  -- enum types
  LOOP
    EXECUTE format('DROP TYPE IF EXISTS public.%I CASCADE', r.typname);
  END LOOP;
END $$;

-- ============================================================
-- 5. Drop private schema and everything in it
-- ============================================================
DROP SCHEMA IF EXISTS private CASCADE;

