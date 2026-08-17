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
BEGIN
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

    INSERT INTO ctfzone.users (name,type,participant_token,verified)
    VALUES ('schema-contract-user-1','user',gen_random_uuid()::text,false)
    RETURNING id INTO first_user_id;
    INSERT INTO ctfzone.users (name,type,participant_token,verified)
    VALUES ('schema-contract-user-2','user',gen_random_uuid()::text,false)
    RETURNING id INTO second_user_id;

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
