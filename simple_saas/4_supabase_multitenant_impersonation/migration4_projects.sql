-- ============================================================
-- MIGRATION 4: Projects — ReBAC demo
--
-- Demonstrates relationship-based access control where the
-- *relations* are managed at the application layer and RLS
-- provides only tenant isolation as a hard boundary.
--
-- Access model:
--   A user can see a project if:
--     (a) they created it, OR
--     (b) someone shared it with them (project_roles row exists)
--   This logic lives in Python (list_accessible_projects), not RLS.
--   RLS ensures no cross-tenant leakage regardless of app bugs.
-- ============================================================

CREATE TABLE public.projects (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid        NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  name       text        NOT NULL,
  created_by uuid        NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.project_roles (
  project_id uuid        NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  user_id    uuid        NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
  granted_by uuid        NOT NULL REFERENCES public.users(user_id) ON DELETE CASCADE,
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (project_id, user_id)
);

ALTER TABLE public.projects      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.project_roles ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- RLS: projects
-- Policies enforce tenant isolation only.
-- Fine-grained access (creator vs. shared) is enforced by the
-- application layer via list_accessible_projects().
-- ============================================================

-- Regular users see all projects in their own tenant.
-- (App layer then filters to owned + shared.)
CREATE POLICY "projects_select_tenant"
  ON public.projects FOR SELECT
  TO authenticated
  USING (tenant_id = (SELECT public.current_user_tenant_id()));

-- Note: SaasCo staff have no special project visibility by default.
-- They must impersonate a tenant user to see that tenant's projects,
-- which goes through the normal ReBAC access check above.

-- Users may only create projects in their own tenant, attributed to themselves.
CREATE POLICY "projects_insert_own"
  ON public.projects FOR INSERT
  TO authenticated
  WITH CHECK (
    tenant_id  = (SELECT public.current_user_tenant_id())
    AND created_by = (SELECT auth.uid())
  );

-- Only the project creator may delete it.
CREATE POLICY "projects_delete_owner"
  ON public.projects FOR DELETE
  TO authenticated
  USING (created_by = (SELECT auth.uid()));

-- ============================================================
-- RLS: project_roles
-- ============================================================

-- Tenant-scoped visibility: you can see sharing records for
-- projects within your tenant.
CREATE POLICY "project_roles_select_tenant"
  ON public.project_roles FOR SELECT
  TO authenticated
  USING (
    project_id IN (
      SELECT id FROM public.projects
      WHERE tenant_id = (SELECT public.current_user_tenant_id())
    )
  );

-- Only the project creator may add sharing records.
CREATE POLICY "project_roles_insert_owner"
  ON public.project_roles FOR INSERT
  TO authenticated
  WITH CHECK (
    project_id IN (
      SELECT id FROM public.projects
      WHERE created_by = (SELECT auth.uid())
    )
  );

-- Only the project creator may revoke sharing.
CREATE POLICY "project_roles_delete_owner"
  ON public.project_roles FOR DELETE
  TO authenticated
  USING (
    project_id IN (
      SELECT id FROM public.projects
      WHERE created_by = (SELECT auth.uid())
    )
  );

-- ============================================================
-- Audit triggers
-- ============================================================

CREATE OR REPLACE TRIGGER audit_projects
  AFTER INSERT OR UPDATE OR DELETE ON public.projects
  FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_fn();

CREATE OR REPLACE TRIGGER audit_project_roles
  AFTER INSERT OR UPDATE OR DELETE ON public.project_roles
  FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_fn();
