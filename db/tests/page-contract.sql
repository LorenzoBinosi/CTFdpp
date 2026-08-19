\set ON_ERROR_STOP on

BEGIN;

DO $$
DECLARE
    custom_page_id integer;
BEGIN
    IF (
        SELECT count(*) FROM ctfzone.pages
        WHERE system_key IN ('home','challenges','scoreboard')
    ) <> 3 THEN
        RAISE EXCEPTION 'the permanent page catalog is incomplete';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM ctfzone.pages
        WHERE page_type='home' AND system_key='home' AND endpoint=''
          AND visibility='public' AND navigation_order=0
    ) THEN
        RAISE EXCEPTION 'the root page identity is invalid';
    END IF;

    INSERT INTO ctfzone.pages
        (label,endpoint,content,page_type,visibility,navigation_order)
    VALUES
        ('About','about/team','<h1>About</h1>','custom','private',70)
    RETURNING id INTO custom_page_id;

    IF NOT EXISTS (
        SELECT 1 FROM ctfzone.pages
        WHERE id=custom_page_id AND revision=1 AND system_key IS NULL
    ) THEN
        RAISE EXCEPTION 'custom page defaults are invalid';
    END IF;

    BEGIN
        UPDATE ctfzone.pages SET visibility='private' WHERE system_key='home';
        RAISE EXCEPTION 'the root page was allowed to become private';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE ctfzone.pages SET endpoint='elsewhere' WHERE system_key='home';
        RAISE EXCEPTION 'the root endpoint was allowed to move';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE ctfzone.pages SET content='<p>mutable</p>' WHERE system_key='challenges';
        RAISE EXCEPTION 'a system page accepted custom content';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE ctfzone.pages SET label='Problems' WHERE system_key='challenges';
        RAISE EXCEPTION 'a system page label was allowed to change';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE ctfzone.pages SET navigation_order=0 WHERE id=custom_page_id;
        RAISE EXCEPTION 'a custom page was allowed to take the reserved root order';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO ctfzone.pages
            (label,endpoint,content,page_type,visibility,navigation_order)
        VALUES ('Bad route','Bad Route','','custom','public',80);
        RAISE EXCEPTION 'an invalid custom endpoint was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO ctfzone.pages
            (label,endpoint,content,page_type,visibility,navigation_order)
        VALUES ('Duplicate','about/team','','custom','public',80);
        RAISE EXCEPTION 'a duplicate page endpoint was accepted';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE ctfzone.pages SET visibility='hidden' WHERE id=custom_page_id;
        RAISE EXCEPTION 'an unknown page visibility was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$$;

ROLLBACK;
