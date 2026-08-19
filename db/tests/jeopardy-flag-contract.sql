\set ON_ERROR_STOP on

BEGIN;

DO $$
DECLARE
    category_id integer;
    challenge_id integer;
    second_challenge_id integer;
    flag_id integer;
    first_user_id integer;
    second_user_id integer;
    category_icon_id uuid := gen_random_uuid();
    pending_category_icon_id uuid := gen_random_uuid();
    disposable_category_id integer;
    disposable_icon_id uuid := gen_random_uuid();
    svg_category_id integer;
    svg_icon_id uuid := gen_random_uuid();
    removal_category_id integer;
    removal_icon_id uuid := gen_random_uuid();
    matching_pending_icon_id uuid := gen_random_uuid();
    unrelated_pending_icon_id uuid := gen_random_uuid();
    post_attach_pending_icon_id uuid := gen_random_uuid();
    stale_icon_id uuid := gen_random_uuid();
    affected_rows integer;
BEGIN
    IF position(
        'FOR SHARE' IN pg_get_functiondef(
            'ctfzone.validate_challenge_category_icon()'::regprocedure
        )
    ) = 0 THEN
        RAISE EXCEPTION 'category icon attachment validation does not lock the object against drift';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema='ctfzone' AND table_name='challenges' AND column_name='public_url'
    ) THEN
        RAISE EXCEPTION 'obsolete challenges.public_url column is still present';
    END IF;

    INSERT INTO ctfzone.challenge_categories (name)
    VALUES ('schema-contract-category')
    RETURNING id INTO category_id;

    IF NOT EXISTS (
        SELECT 1 FROM ctfzone.challenge_categories
        WHERE id=category_id AND logo_key IS NULL AND logo_color IS NULL AND icon_object_id IS NULL
    ) THEN
        RAISE EXCEPTION 'challenge category defaults are invalid';
    END IF;

    UPDATE ctfzone.challenge_categories
    SET logo_key='forensics',logo_color='#123abc'
    WHERE id=category_id;
    IF (SELECT jsonb_build_array(logo_key,logo_color) FROM ctfzone.challenge_categories WHERE id=category_id)
        IS DISTINCT FROM '["forensics","#123abc"]'::jsonb
    THEN
        RAISE EXCEPTION 'challenge category semantic logo was not stored';
    END IF;

    BEGIN
        UPDATE ctfzone.challenge_categories
        SET logo_key='dinosaur'
        WHERE id=category_id;
        RAISE EXCEPTION 'unsupported challenge category logo was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        UPDATE ctfzone.challenge_categories
        SET logo_color='red'
        WHERE id=category_id;
        RAISE EXCEPTION 'invalid challenge category logo color was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO ctfzone.challenge_categories (name,logo_color)
        VALUES ('schema-contract-color-without-logo','#123abc');
        RAISE EXCEPTION 'challenge category color without a logo was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO ctfzone.challenge_categories (name)
        VALUES (U&'schema-contract-\202Ecategory');
        RAISE EXCEPTION 'bidirectional category name control was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO ctfzone.users (name,type,participant_token,verified)
    VALUES ('schema-contract-user-1','user',gen_random_uuid()::text,false)
    RETURNING id INTO first_user_id;
    INSERT INTO ctfzone.users (name,type,participant_token,verified)
    VALUES ('schema-contract-user-2','user',gen_random_uuid()::text,false)
    RETURNING id INTO second_user_id;

    INSERT INTO ctfzone.challenge_categories (name)
    VALUES ('schema-contract-svg-category')
    RETURNING id INTO svg_category_id;
    INSERT INTO ctfzone.stored_objects (
        id,bucket,object_key,upload_key,purpose,status,authorization_scope,
        owner_user_id,idempotency_key,category_id,original_filename,content_type,
        expected_size,actual_size,expected_checksum,actual_checksum,
        upload_expires_at,ready_at,metadata
    ) VALUES (
        svg_icon_id,'contract','objects/category-icon-svg','uploads/category-icon-svg',
        'category_icon','ready','target',first_user_id,'category-icon-svg',svg_category_id,
        'icon.svg','image/svg+xml',128,128,repeat('9',64),repeat('9',64),
        now()+interval '15 minutes',now(),
        '{"format":"svg","width":128,"height":128,"animated":false,"sanitized":true}'::jsonb
    );
    UPDATE ctfzone.challenge_categories SET icon_object_id=svg_icon_id WHERE id=svg_category_id;

    BEGIN
        UPDATE ctfzone.stored_objects
        SET metadata=metadata-'sanitized'
        WHERE id=svg_icon_id;
        SET CONSTRAINTS stored_objects_validate_attached_category_icon IMMEDIATE;
        RAISE EXCEPTION 'attached SVG category icon lost its sanitizer proof';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    SET CONSTRAINTS stored_objects_validate_attached_category_icon DEFERRED;

    INSERT INTO ctfzone.challenges (
        name,value,category,category_id,challenge_type,exposure,type,state,logic,position
    ) VALUES (
        'schema-contract-challenge',100,'schema-contract-category',category_id,
        'jeopardy','private','standard','hidden','any',0
    ) RETURNING id INTO challenge_id;
    INSERT INTO ctfzone.challenges (
        name,value,category,category_id,challenge_type,exposure,type,state,logic,position
    ) VALUES (
        'schema-contract-challenge-2',100,'schema-contract-category',category_id,
        'jeopardy','private','standard','hidden','any',1
    ) RETURNING id INTO second_challenge_id;

    UPDATE ctfzone.challenge_categories
    SET name='schema-contract-category-renamed'
    WHERE id=category_id;
    IF (
        SELECT COUNT(*) FROM ctfzone.challenges challenge
        WHERE challenge.category_id=(
            SELECT category.id FROM ctfzone.challenge_categories category
            WHERE category.name='schema-contract-category-renamed'
        )
          AND challenge.category='schema-contract-category-renamed'
    ) <> 2 THEN
        RAISE EXCEPTION 'challenge category rename did not cascade to challenges';
    END IF;

    INSERT INTO ctfzone.stored_objects (
        id,bucket,object_key,upload_key,purpose,status,authorization_scope,
        owner_user_id,idempotency_key,category_id,original_filename,content_type,
        expected_size,actual_size,expected_checksum,actual_checksum,
        upload_expires_at,ready_at,metadata
    ) VALUES (
        category_icon_id,'contract','objects/category-icon','uploads/category-icon',
        'category_icon','ready','target',first_user_id,'category-icon-ready',category_id,
        'icon.png','image/png',128,128,repeat('a',64),repeat('a',64),
        now()+interval '15 minutes',now(),
        '{"format":"png","width":128,"height":128,"animated":false}'::jsonb
    );
    UPDATE ctfzone.challenge_categories
    SET icon_object_id=category_icon_id
    WHERE id=category_id;

    BEGIN
        UPDATE ctfzone.stored_objects
        SET metadata='{}'::jsonb
        WHERE id=category_icon_id;
        SET CONSTRAINTS stored_objects_validate_attached_category_icon IMMEDIATE;
        RAISE EXCEPTION 'attached category icon validation metadata was cleared';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    SET CONSTRAINTS stored_objects_validate_attached_category_icon DEFERRED;

    BEGIN
        UPDATE ctfzone.stored_objects
        SET status='deleting'
        WHERE id=category_icon_id;
        SET CONSTRAINTS stored_objects_validate_attached_category_icon IMMEDIATE;
        RAISE EXCEPTION 'attached category icon lifecycle drift was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
    SET CONSTRAINTS stored_objects_validate_attached_category_icon DEFERRED;

    INSERT INTO ctfzone.stored_objects (
        id,bucket,object_key,upload_key,purpose,status,authorization_scope,
        owner_user_id,idempotency_key,category_id,original_filename,content_type,
        expected_size,expected_checksum,upload_expires_at,metadata
    ) VALUES (
        pending_category_icon_id,'contract','objects/category-icon-pending',
        'uploads/category-icon-pending','category_icon','pending','target',first_user_id,
        'category-icon-pending',category_id,'pending.png','image/png',128,repeat('b',64),
        now()+interval '15 minutes',jsonb_build_object(
            'expected_icon_object_id',category_icon_id
        )
    );
    BEGIN
        UPDATE ctfzone.challenge_categories
        SET icon_object_id=pending_category_icon_id
        WHERE id=category_id;
        RAISE EXCEPTION 'pending object was attached as a category icon';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO ctfzone.stored_objects (
            bucket,object_key,upload_key,purpose,status,authorization_scope,
            owner_user_id,idempotency_key,category_id,original_filename,content_type,
            expected_size,actual_size,expected_checksum,actual_checksum,
            upload_expires_at,ready_at,metadata
        ) VALUES (
            'contract','objects/category-icon-missing-metadata',
            'uploads/category-icon-missing-metadata','category_icon','ready','target',
            first_user_id,'category-icon-missing-metadata',category_id,
            'missing-metadata.png','image/png',128,128,repeat('e',64),repeat('e',64),
            now()+interval '15 minutes',now(),'{}'::jsonb
        );
        RAISE EXCEPTION 'ready category icon with missing validation metadata was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO ctfzone.stored_objects (
            bucket,object_key,upload_key,purpose,status,authorization_scope,
            owner_user_id,idempotency_key,category_id,original_filename,content_type,
            expected_size,actual_size,expected_checksum,actual_checksum,
            upload_expires_at,ready_at,metadata
        ) VALUES (
            'contract','objects/category-icon-invalid','uploads/category-icon-invalid',
            'category_icon','ready','target',first_user_id,'category-icon-invalid',category_id,
            'invalid.png','image/png',128,128,repeat('c',64),repeat('c',64),
            now()+interval '15 minutes',now(),
            '{"format":"png","width":64,"height":128,"animated":false}'::jsonb
        );
        RAISE EXCEPTION 'invalid ready category icon metadata was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO ctfzone.challenge_categories (name)
    VALUES ('schema-contract-disposable-category')
    RETURNING id INTO disposable_category_id;
    INSERT INTO ctfzone.stored_objects (
        id,bucket,object_key,upload_key,purpose,status,authorization_scope,
        owner_user_id,idempotency_key,category_id,original_filename,content_type,
        expected_size,actual_size,expected_checksum,actual_checksum,
        upload_expires_at,ready_at,metadata
    ) VALUES (
        disposable_icon_id,'contract','objects/category-icon-disposable',
        'uploads/category-icon-disposable','category_icon','ready','target',first_user_id,
        'category-icon-disposable',disposable_category_id,'disposable.png','image/png',
        128,128,repeat('d',64),repeat('d',64),now()+interval '15 minutes',now(),
        '{"format":"png","width":128,"height":128,"animated":false}'::jsonb
    );
    UPDATE ctfzone.challenge_categories
    SET icon_object_id=disposable_icon_id
    WHERE id=disposable_category_id;
    DELETE FROM ctfzone.challenge_categories WHERE id=disposable_category_id;
    IF NOT EXISTS (
        SELECT 1 FROM ctfzone.stored_objects object
        WHERE object.id=disposable_icon_id
          AND object.status='deleting' AND object.category_id IS NULL
    ) OR (
        SELECT COUNT(*) FROM ctfzone.object_operations operation
        WHERE operation.object_id=disposable_icon_id AND operation.status='pending'
          AND operation.operation IN ('delete','delete_upload')
    ) <> 2 THEN
        RAISE EXCEPTION 'category deletion did not durably retire its icon';
    END IF;

    -- Mirrors the API's expected-pointer/delete and attach fences. A stale
    -- removal cannot detach a newer icon, and every winning attach or removal
    -- retires all older pending uploads so NULL -> A -> NULL cannot revive one.
    INSERT INTO ctfzone.challenge_categories (name)
    VALUES ('schema-contract-removal-category')
    RETURNING id INTO removal_category_id;
    INSERT INTO ctfzone.stored_objects (
        id,bucket,object_key,upload_key,purpose,status,authorization_scope,
        owner_user_id,idempotency_key,category_id,original_filename,content_type,
        expected_size,expected_checksum,upload_expires_at,metadata
    ) VALUES (
        unrelated_pending_icon_id,'contract','objects/category-icon-removal-aba',
        'uploads/category-icon-removal-aba','category_icon','pending','target',
        first_user_id,'category-icon-removal-aba',removal_category_id,
        'aba.png','image/png',128,repeat('0',64),now()+interval '15 minutes',
        jsonb_build_object('expected_icon_object_id',NULL)
    );
    INSERT INTO ctfzone.stored_objects (
        id,bucket,object_key,upload_key,purpose,status,authorization_scope,
        owner_user_id,idempotency_key,category_id,original_filename,content_type,
        expected_size,actual_size,expected_checksum,actual_checksum,
        upload_expires_at,ready_at,metadata
    ) VALUES (
        removal_icon_id,'contract','objects/category-icon-removal',
        'uploads/category-icon-removal','category_icon','ready','target',first_user_id,
        'category-icon-removal',removal_category_id,'removal.png','image/png',128,128,
        repeat('f',64),repeat('f',64),now()+interval '15 minutes',now(),
        '{"format":"png","width":128,"height":128,"animated":false}'::jsonb
    );
    UPDATE ctfzone.challenge_categories
    SET icon_object_id=removal_icon_id
    WHERE id=removal_category_id;
    UPDATE ctfzone.stored_objects AS object
    SET status='deleting',revision=revision+1
    WHERE object.category_id=removal_category_id
      AND object.purpose='category_icon'
      AND object.status='pending'
      AND object.id<>removal_icon_id;
    IF NOT EXISTS (
        SELECT 1 FROM ctfzone.stored_objects
        WHERE id=unrelated_pending_icon_id AND status='deleting'
    ) THEN
        RAISE EXCEPTION 'winning NULL-base icon upload did not retire its ABA competitor';
    END IF;
    INSERT INTO ctfzone.stored_objects (
        id,bucket,object_key,upload_key,purpose,status,authorization_scope,
        owner_user_id,idempotency_key,category_id,original_filename,content_type,
        expected_size,expected_checksum,upload_expires_at,metadata
    ) VALUES
    (
        matching_pending_icon_id,'contract','objects/category-icon-removal-matching',
        'uploads/category-icon-removal-matching','category_icon','pending','target',
        first_user_id,'category-icon-removal-matching',removal_category_id,
        'matching.png','image/png',128,repeat('1',64),now()+interval '15 minutes',
        jsonb_build_object('expected_icon_object_id',removal_icon_id)
    ),
    (
        post_attach_pending_icon_id,'contract','objects/category-icon-removal-post-attach',
        'uploads/category-icon-removal-post-attach','category_icon','pending','target',
        first_user_id,'category-icon-removal-post-attach',removal_category_id,
        'post-attach.png','image/png',128,repeat('2',64),now()+interval '15 minutes',
        jsonb_build_object('expected_icon_object_id',stale_icon_id)
    );

    UPDATE ctfzone.challenge_categories
    SET icon_object_id=NULL
    WHERE id=removal_category_id AND icon_object_id=stale_icon_id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 0 OR NOT EXISTS (
        SELECT 1 FROM ctfzone.challenge_categories
        WHERE id=removal_category_id AND icon_object_id=removal_icon_id
    ) THEN
        RAISE EXCEPTION 'stale category icon removal changed the current pointer';
    END IF;

    UPDATE ctfzone.challenge_categories
    SET icon_object_id=NULL
    WHERE id=removal_category_id AND icon_object_id=removal_icon_id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
        RAISE EXCEPTION 'current category icon removal fence did not match';
    END IF;
    UPDATE ctfzone.stored_objects AS object
    SET status='deleting',revision=revision+1
    WHERE object.category_id=removal_category_id AND object.purpose='category_icon'
      AND (
          object.id=removal_icon_id
          OR object.status='pending'
      );
    IF NOT EXISTS (
        SELECT 1 FROM ctfzone.stored_objects
        WHERE id=removal_icon_id AND status='deleting'
    ) OR NOT EXISTS (
        SELECT 1 FROM ctfzone.stored_objects
        WHERE id=matching_pending_icon_id AND status='deleting'
    ) OR NOT EXISTS (
        SELECT 1 FROM ctfzone.stored_objects
        WHERE id=unrelated_pending_icon_id AND status='deleting'
    ) OR NOT EXISTS (
        SELECT 1 FROM ctfzone.stored_objects
        WHERE id=post_attach_pending_icon_id AND status='deleting'
    ) THEN
        RAISE EXCEPTION 'category icon removal did not retire every stale pending upload';
    END IF;

    BEGIN
        INSERT INTO ctfzone.challenges (
            name,max_attempts,value,category,category_id,challenge_type,
            exposure,type,state,logic,position
        ) VALUES (
            'schema-contract-negative-attempts',-1,100,'schema-contract-category',category_id,
            'jeopardy','private','standard','hidden','any',2
        );
        RAISE EXCEPTION 'negative challenge max_attempts was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO ctfzone.challenges (
            name,connection_info,value,category,category_id,challenge_type,
            exposure,type,state,logic,position
        ) VALUES (
            'schema-contract-long-connection',repeat('x',4097),100,
            'schema-contract-category',category_id,'jeopardy','public',
            'standard','hidden','any',3
        );
        RAISE EXCEPTION 'oversized challenge connection_info was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    INSERT INTO ctfzone.flags (challenge_id,type,content,data)
    VALUES (
        challenge_id,
        'generated',
        'flag{test}',
        '{"case_sensitive":true,"leet_variation":true,"accept_other_users":false}'::jsonb
    ) RETURNING id INTO flag_id;

    -- Mirrors the API allocation write, including revision and mask metadata.
    INSERT INTO ctfzone.user_challenge_flags (
        flag_id,challenge_id,user_id,definition_revision,match_tag,random_token,
        leet_mask,leet_position_count
    ) VALUES (
        flag_id,challenge_id,first_user_id,1,decode(repeat('11',32),'hex'),NULL,1,4
    );

    INSERT INTO ctfzone.admin_create_idempotency (
        actor_user_id,operation,idempotency_key,request_sha256,resource_id,response_data
    ) VALUES (
        first_user_id,'challenge.create','schema-contract-key',
        decode(repeat('aa',32),'hex'),challenge_id,jsonb_build_object('id',challenge_id)
    );

    BEGIN
        DELETE FROM ctfzone.users WHERE id=first_user_id;
        RAISE EXCEPTION 'user with a personalized flag was deleted';
    EXCEPTION WHEN foreign_key_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO ctfzone.admin_create_idempotency (
            actor_user_id,operation,idempotency_key,request_sha256,resource_id,response_data
        ) VALUES (
            first_user_id,'challenge.create','schema-contract-key',
            decode(repeat('bb',32),'hex'),challenge_id,jsonb_build_object('id',challenge_id)
        );
        RAISE EXCEPTION 'duplicate create idempotency key was accepted';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO ctfzone.user_challenge_flags (
            flag_id,challenge_id,user_id,definition_revision,match_tag,random_token,
            leet_mask,leet_position_count
        ) VALUES (
            flag_id,challenge_id,second_user_id,1,decode(repeat('11',32),'hex'),NULL,2,4
        );
        RAISE EXCEPTION 'duplicate challenge match tag was accepted';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO ctfzone.user_challenge_flags (
            flag_id,challenge_id,user_id,definition_revision,match_tag,random_token,
            leet_mask,leet_position_count
        ) VALUES (
            flag_id,challenge_id,second_user_id,1,decode(repeat('22',32),'hex'),NULL,16,4
        );
        RAISE EXCEPTION 'out-of-range leet mask was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO ctfzone.user_challenge_flags (
            flag_id,challenge_id,user_id,definition_revision,match_tag,random_token,
            leet_mask,leet_position_count
        ) VALUES (
            flag_id,second_challenge_id,second_user_id,1,
            decode(repeat('33',32),'hex'),NULL,2,4
        );
        RAISE EXCEPTION 'flag assignment accepted a mismatched challenge';
    EXCEPTION WHEN foreign_key_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO ctfzone.user_challenge_flags (
            flag_id,challenge_id,user_id,definition_revision,match_tag,random_token,
            leet_mask,leet_position_count
        ) VALUES (
            flag_id,challenge_id,second_user_id,1,
            decode(repeat('44',32),'hex'),NULL,2,NULL
        );
        RAISE EXCEPTION 'half-null leet metadata was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$$;

ROLLBACK;
