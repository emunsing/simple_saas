-- ============================================================
-- MIGRATION 6: Fix infinite RLS recursion on projects
--
-- Migration 5 introduced projects_select_rebac which uses:
--   EXISTS (SELECT 1 FROM project_roles WHERE project_id = id AND user_id = auth.uid())
--
-- Migration 4's project_roles_select_tenant uses:
--   project_id IN (SELECT id FROM public.projects WHERE tenant_id = ...)
--
-- These policies form a cycle:
--   querying projects  → evaluates project_roles policy
--                      → queries projects to check tenant scope
--                      → evaluates projects policy again → 42P17 infinite recursion
--
-- Fix: wrap the project_roles lookup in a SECURITY DEFINER function.
-- SECURITY DEFINER runs as the function owner (bypasses RLS on project_roles),
-- breaking the cycle.  This is the same pattern used in migration1 for
-- current_user_tenant_id() to avoid recursion on the users/tenants tables.
-- ============================================================

-- Helper: returns true if the current user holds a project_role for p_project_id.
-- SECURITY DEFINER bypasses RLS on project_roles so this does not re-trigger
-- project_roles_select_tenant, which in turn would re-trigger projects_select_rebac.
CREATE OR REPLACE FUNCTION public.current_user_has_project_role(p_project_id uuid)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.project_roles
    WHERE project_id = p_project_id
      AND user_id = (SELECT auth.uid())
  );
$$;

GRANT EXECUTE ON FUNCTION public.current_user_has_project_role TO authenticated;

-- Replace the policy introduced in migration5 with one that calls the
-- SECURITY DEFINER helper instead of a bare subquery on project_roles.
DROP POLICY IF EXISTS "projects_select_rebac" ON public.projects;

CREATE POLICY "projects_select_rebac"
  ON public.projects FOR SELECT
  TO authenticated
  USING (
    -- Hard tenant boundary
    tenant_id = (SELECT public.current_user_tenant_id())
    AND (
      -- Creator always sees their own projects
      created_by = (SELECT auth.uid())
      -- Shared projects — looked up via SECURITY DEFINER to avoid RLS cycle
      OR (SELECT public.current_user_has_project_role(id))
    )
  );
