-- CTFZone 1.0.0 portal schema.
-- Generated from the known-working PostgreSQL 16 schema; contains no data.
-- This is a fresh-install baseline executed once by the PostgreSQL image when
-- PGDATA is empty; later schema evolution must not rerun this file in place.


-- Dumped from database version 16.14
-- Dumped by pg_dump version 16.14

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: awards; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.awards (
    id integer NOT NULL,
    user_id integer,
    team_id integer,
    type character varying(80),
    name character varying(80),
    description text,
    date timestamp without time zone,
    value integer,
    category character varying(80),
    icon text,
    requirements json
);


--
-- Name: awards_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.awards_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: awards_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.awards_id_seq OWNED BY ctfzone.awards.id;


--
-- Name: brackets; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.brackets (
    id integer NOT NULL,
    name character varying(255),
    description text,
    type character varying(80)
);


--
-- Name: brackets_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.brackets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: brackets_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.brackets_id_seq OWNED BY ctfzone.brackets.id;


--
-- Name: challenge_topics; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.challenge_topics (
    id integer NOT NULL,
    challenge_id integer,
    topic_id integer
);


--
-- Name: challenge_topics_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.challenge_topics_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: challenge_topics_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.challenge_topics_id_seq OWNED BY ctfzone.challenge_topics.id;


--
-- Name: challenges; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.challenges (
    id integer NOT NULL,
    name character varying(80),
    description text,
    attribution text,
    connection_info text,
    next_id integer,
    max_attempts integer,
    value integer,
    category character varying(80),
    type character varying(80),
    state character varying(80) NOT NULL,
    logic character varying(80) NOT NULL,
    initial integer,
    minimum integer,
    decay integer,
    "position" integer NOT NULL,
    function character varying(32),
    requirements json
);


--
-- Name: challenges_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.challenges_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: challenges_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.challenges_id_seq OWNED BY ctfzone.challenges.id;


--
-- Name: comments; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.comments (
    id integer NOT NULL,
    type character varying(80),
    content text,
    date timestamp without time zone,
    author_id integer,
    challenge_id integer,
    user_id integer,
    team_id integer,
    page_id integer
);


--
-- Name: comments_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.comments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: comments_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.comments_id_seq OWNED BY ctfzone.comments.id;


--
-- Name: config; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.config (
    id integer NOT NULL,
    key text,
    value text
);


--
-- Name: config_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.config_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: config_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.config_id_seq OWNED BY ctfzone.config.id;


--
-- Name: dynamic_challenge; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.dynamic_challenge (
    id integer NOT NULL,
    dynamic_initial integer,
    dynamic_minimum integer,
    dynamic_decay integer,
    dynamic_function character varying(32)
);


--
-- Name: field_entries; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.field_entries (
    id integer NOT NULL,
    type character varying(80),
    value json,
    field_id integer,
    user_id integer,
    team_id integer
);


--
-- Name: field_entries_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.field_entries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: field_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.field_entries_id_seq OWNED BY ctfzone.field_entries.id;


--
-- Name: fields; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.fields (
    id integer NOT NULL,
    name text,
    type character varying(80),
    field_type character varying(80),
    description text,
    required boolean,
    public boolean,
    editable boolean
);


--
-- Name: fields_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.fields_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fields_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.fields_id_seq OWNED BY ctfzone.fields.id;


--
-- Name: files; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.files (
    id integer NOT NULL,
    type character varying(80),
    location text,
    sha1sum character varying(40),
    challenge_id integer,
    page_id integer,
    solution_id integer
);


--
-- Name: files_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.files_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: files_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.files_id_seq OWNED BY ctfzone.files.id;


--
-- Name: flags; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.flags (
    id integer NOT NULL,
    challenge_id integer,
    type character varying(80),
    content text,
    data text
);


--
-- Name: flags_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.flags_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: flags_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.flags_id_seq OWNED BY ctfzone.flags.id;


--
-- Name: hints; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.hints (
    id integer NOT NULL,
    title character varying(80),
    type character varying(80),
    challenge_id integer,
    content text,
    cost integer,
    requirements json
);


--
-- Name: hints_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.hints_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: hints_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.hints_id_seq OWNED BY ctfzone.hints.id;


--
-- Name: notifications; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.notifications (
    id integer NOT NULL,
    title text,
    content text,
    date timestamp without time zone,
    user_id integer,
    team_id integer
);


--
-- Name: notifications_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.notifications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: notifications_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.notifications_id_seq OWNED BY ctfzone.notifications.id;


--
-- Name: pages; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.pages (
    id integer NOT NULL,
    title character varying(80),
    route character varying(128),
    content text,
    draft boolean,
    hidden boolean,
    auth_required boolean,
    format character varying(80),
    link_target character varying(80)
);


--
-- Name: pages_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.pages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: pages_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.pages_id_seq OWNED BY ctfzone.pages.id;


--
-- Name: ratings; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.ratings (
    id integer NOT NULL,
    user_id integer,
    challenge_id integer,
    value integer,
    review character varying(2000),
    date timestamp without time zone
);


--
-- Name: ratings_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.ratings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ratings_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.ratings_id_seq OWNED BY ctfzone.ratings.id;


--
-- Name: registration_email_allowlist; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.registration_email_allowlist (
    id integer NOT NULL,
    email character varying(128) NOT NULL,
    created timestamp without time zone NOT NULL
);


--
-- Name: registration_email_allowlist_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.registration_email_allowlist_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: registration_email_allowlist_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.registration_email_allowlist_id_seq OWNED BY ctfzone.registration_email_allowlist.id;



--
-- Name: session_activity; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.session_activity (
    id integer NOT NULL,
    user_id integer NOT NULL,
    session_id character varying(36),
    api_token_id integer,
    credential_type character varying(16) NOT NULL,
    credential_label character varying(128) NOT NULL,
    method character varying(8) NOT NULL,
    endpoint character varying(255) NOT NULL,
    status_code integer NOT NULL,
    ip character varying(46) NOT NULL,
    ip_changed boolean NOT NULL,
    date timestamp without time zone NOT NULL
);


--
-- Name: session_activity_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.session_activity_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: session_activity_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.session_activity_id_seq OWNED BY ctfzone.session_activity.id;


--
-- Name: solutions; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.solutions (
    id integer NOT NULL,
    challenge_id integer,
    content text,
    state character varying(80) NOT NULL
);


--
-- Name: solutions_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.solutions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: solutions_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.solutions_id_seq OWNED BY ctfzone.solutions.id;


--
-- Name: solves; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.solves (
    id integer NOT NULL,
    challenge_id integer,
    user_id integer,
    team_id integer
);


--
-- Name: submissions; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.submissions (
    id integer NOT NULL,
    challenge_id integer,
    user_id integer,
    team_id integer,
    ip character varying(46),
    provided text,
    type character varying(32),
    date timestamp without time zone
);


--
-- Name: submissions_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.submissions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: submissions_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.submissions_id_seq OWNED BY ctfzone.submissions.id;


--
-- Name: tags; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.tags (
    id integer NOT NULL,
    challenge_id integer,
    value character varying(80)
);


--
-- Name: tags_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.tags_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tags_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.tags_id_seq OWNED BY ctfzone.tags.id;


--
-- Name: teams; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.teams (
    id integer NOT NULL,
    name character varying(128),
    email character varying(128),
    password character varying(128),
    secret character varying(128),
    participant_token character varying(36) NOT NULL,
    participant_token_last_rotated timestamp without time zone,
    website character varying(128),
    affiliation character varying(128),
    country character varying(32),
    bracket_id integer,
    hidden boolean,
    banned boolean,
    captain_id integer,
    created timestamp without time zone
);


--
-- Name: teams_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.teams_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: teams_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.teams_id_seq OWNED BY ctfzone.teams.id;


--
-- Name: tokens; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.tokens (
    id integer NOT NULL,
    type character varying(32),
    user_id integer,
    created timestamp without time zone,
    expiration timestamp without time zone,
    description text,
    value character varying(128)
);


--
-- Name: tokens_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.tokens_id_seq OWNED BY ctfzone.tokens.id;


--
-- Name: topics; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.topics (
    id integer NOT NULL,
    value character varying(255)
);


--
-- Name: topics_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.topics_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: topics_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.topics_id_seq OWNED BY ctfzone.topics.id;


--
-- Name: tracking; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.tracking (
    id integer NOT NULL,
    type character varying(32),
    ip character varying(46),
    target integer,
    user_id integer,
    date timestamp without time zone
);


--
-- Name: tracking_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.tracking_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tracking_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.tracking_id_seq OWNED BY ctfzone.tracking.id;


--
-- Name: unlocks; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.unlocks (
    id integer NOT NULL,
    user_id integer,
    team_id integer,
    target integer,
    date timestamp without time zone,
    type character varying(32)
);


--
-- Name: unlocks_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.unlocks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: unlocks_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.unlocks_id_seq OWNED BY ctfzone.unlocks.id;


--
-- Name: user_sessions; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.user_sessions (
    id character varying(36) NOT NULL,
    user_id integer NOT NULL,
    created timestamp without time zone NOT NULL,
    last_seen timestamp without time zone NOT NULL,
    csrf_nonce character varying(64),
    initial_ip character varying(46) NOT NULL,
    last_ip character varying(46) NOT NULL,
    revoked_at timestamp without time zone,
    revoked_by_user_id integer
);


--
-- Name: users; Type: TABLE; Schema: ctfzone; Owner: -
--

CREATE TABLE ctfzone.users (
    id integer NOT NULL,
    name character varying(128),
    password character varying(128),
    email character varying(128),
    type character varying(80),
    secret character varying(128),
    participant_token character varying(36) NOT NULL,
    participant_token_last_rotated timestamp without time zone,
    website character varying(128),
    affiliation character varying(128),
    country character varying(32),
    bracket_id integer,
    hidden boolean,
    banned boolean,
    verified boolean,
    language character varying(32),
    change_password boolean,
    team_id integer,
    created timestamp without time zone
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: ctfzone; Owner: -
--

CREATE SEQUENCE ctfzone.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: ctfzone; Owner: -
--

ALTER SEQUENCE ctfzone.users_id_seq OWNED BY ctfzone.users.id;


--
-- Name: awards id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.awards ALTER COLUMN id SET DEFAULT nextval('ctfzone.awards_id_seq'::regclass);


--
-- Name: brackets id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.brackets ALTER COLUMN id SET DEFAULT nextval('ctfzone.brackets_id_seq'::regclass);


--
-- Name: challenge_topics id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.challenge_topics ALTER COLUMN id SET DEFAULT nextval('ctfzone.challenge_topics_id_seq'::regclass);


--
-- Name: challenges id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.challenges ALTER COLUMN id SET DEFAULT nextval('ctfzone.challenges_id_seq'::regclass);


--
-- Name: comments id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.comments ALTER COLUMN id SET DEFAULT nextval('ctfzone.comments_id_seq'::regclass);


--
-- Name: config id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.config ALTER COLUMN id SET DEFAULT nextval('ctfzone.config_id_seq'::regclass);


--
-- Name: field_entries id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.field_entries ALTER COLUMN id SET DEFAULT nextval('ctfzone.field_entries_id_seq'::regclass);


--
-- Name: fields id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.fields ALTER COLUMN id SET DEFAULT nextval('ctfzone.fields_id_seq'::regclass);


--
-- Name: files id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.files ALTER COLUMN id SET DEFAULT nextval('ctfzone.files_id_seq'::regclass);


--
-- Name: flags id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.flags ALTER COLUMN id SET DEFAULT nextval('ctfzone.flags_id_seq'::regclass);


--
-- Name: hints id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.hints ALTER COLUMN id SET DEFAULT nextval('ctfzone.hints_id_seq'::regclass);


--
-- Name: notifications id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.notifications ALTER COLUMN id SET DEFAULT nextval('ctfzone.notifications_id_seq'::regclass);


--
-- Name: pages id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.pages ALTER COLUMN id SET DEFAULT nextval('ctfzone.pages_id_seq'::regclass);


--
-- Name: ratings id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.ratings ALTER COLUMN id SET DEFAULT nextval('ctfzone.ratings_id_seq'::regclass);


--
-- Name: registration_email_allowlist id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.registration_email_allowlist ALTER COLUMN id SET DEFAULT nextval('ctfzone.registration_email_allowlist_id_seq'::regclass);


--
-- Name: session_activity id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.session_activity ALTER COLUMN id SET DEFAULT nextval('ctfzone.session_activity_id_seq'::regclass);


--
-- Name: solutions id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.solutions ALTER COLUMN id SET DEFAULT nextval('ctfzone.solutions_id_seq'::regclass);


--
-- Name: submissions id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.submissions ALTER COLUMN id SET DEFAULT nextval('ctfzone.submissions_id_seq'::regclass);


--
-- Name: tags id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.tags ALTER COLUMN id SET DEFAULT nextval('ctfzone.tags_id_seq'::regclass);


--
-- Name: teams id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.teams ALTER COLUMN id SET DEFAULT nextval('ctfzone.teams_id_seq'::regclass);


--
-- Name: tokens id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.tokens ALTER COLUMN id SET DEFAULT nextval('ctfzone.tokens_id_seq'::regclass);


--
-- Name: topics id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.topics ALTER COLUMN id SET DEFAULT nextval('ctfzone.topics_id_seq'::regclass);


--
-- Name: tracking id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.tracking ALTER COLUMN id SET DEFAULT nextval('ctfzone.tracking_id_seq'::regclass);


--
-- Name: unlocks id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.unlocks ALTER COLUMN id SET DEFAULT nextval('ctfzone.unlocks_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.users ALTER COLUMN id SET DEFAULT nextval('ctfzone.users_id_seq'::regclass);


--
-- Name: awards awards_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.awards
    ADD CONSTRAINT awards_pkey PRIMARY KEY (id);


--
-- Name: brackets brackets_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.brackets
    ADD CONSTRAINT brackets_pkey PRIMARY KEY (id);


--
-- Name: challenge_topics challenge_topics_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.challenge_topics
    ADD CONSTRAINT challenge_topics_pkey PRIMARY KEY (id);


--
-- Name: challenges challenges_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.challenges
    ADD CONSTRAINT challenges_pkey PRIMARY KEY (id);


--
-- Name: comments comments_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.comments
    ADD CONSTRAINT comments_pkey PRIMARY KEY (id);


--
-- Name: config config_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.config
    ADD CONSTRAINT config_pkey PRIMARY KEY (id);


--
-- Name: dynamic_challenge dynamic_challenge_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.dynamic_challenge
    ADD CONSTRAINT dynamic_challenge_pkey PRIMARY KEY (id);


--
-- Name: field_entries field_entries_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.field_entries
    ADD CONSTRAINT field_entries_pkey PRIMARY KEY (id);


--
-- Name: fields fields_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.fields
    ADD CONSTRAINT fields_pkey PRIMARY KEY (id);


--
-- Name: files files_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.files
    ADD CONSTRAINT files_pkey PRIMARY KEY (id);


--
-- Name: flags flags_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.flags
    ADD CONSTRAINT flags_pkey PRIMARY KEY (id);


--
-- Name: hints hints_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.hints
    ADD CONSTRAINT hints_pkey PRIMARY KEY (id);


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);


--
-- Name: pages pages_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.pages
    ADD CONSTRAINT pages_pkey PRIMARY KEY (id);


--
-- Name: pages pages_route_key; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.pages
    ADD CONSTRAINT pages_route_key UNIQUE (route);


--
-- Name: ratings ratings_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.ratings
    ADD CONSTRAINT ratings_pkey PRIMARY KEY (id);


--
-- Name: ratings ratings_user_id_challenge_id_key; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.ratings
    ADD CONSTRAINT ratings_user_id_challenge_id_key UNIQUE (user_id, challenge_id);


--
-- Name: registration_email_allowlist registration_email_allowlist_email_key; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.registration_email_allowlist
    ADD CONSTRAINT registration_email_allowlist_email_key UNIQUE (email);


--
-- Name: registration_email_allowlist registration_email_allowlist_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.registration_email_allowlist
    ADD CONSTRAINT registration_email_allowlist_pkey PRIMARY KEY (id);


--
-- Name: session_activity session_activity_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.session_activity
    ADD CONSTRAINT session_activity_pkey PRIMARY KEY (id);


--
-- Name: solutions solutions_challenge_id_key; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.solutions
    ADD CONSTRAINT solutions_challenge_id_key UNIQUE (challenge_id);


--
-- Name: solutions solutions_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.solutions
    ADD CONSTRAINT solutions_pkey PRIMARY KEY (id);


--
-- Name: solves solves_challenge_id_team_id_key; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.solves
    ADD CONSTRAINT solves_challenge_id_team_id_key UNIQUE (challenge_id, team_id);


--
-- Name: solves solves_challenge_id_user_id_key; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.solves
    ADD CONSTRAINT solves_challenge_id_user_id_key UNIQUE (challenge_id, user_id);


--
-- Name: solves solves_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.solves
    ADD CONSTRAINT solves_pkey PRIMARY KEY (id);


--
-- Name: submissions submissions_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.submissions
    ADD CONSTRAINT submissions_pkey PRIMARY KEY (id);


--
-- Name: tags tags_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.tags
    ADD CONSTRAINT tags_pkey PRIMARY KEY (id);


--
-- Name: teams teams_email_key; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.teams
    ADD CONSTRAINT teams_email_key UNIQUE (email);


--
-- Name: teams teams_participant_token_key; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.teams
    ADD CONSTRAINT teams_participant_token_key UNIQUE (participant_token);


--
-- Name: teams teams_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.teams
    ADD CONSTRAINT teams_pkey PRIMARY KEY (id);


--
-- Name: tokens tokens_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.tokens
    ADD CONSTRAINT tokens_pkey PRIMARY KEY (id);


--
-- Name: tokens tokens_value_key; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.tokens
    ADD CONSTRAINT tokens_value_key UNIQUE (value);


--
-- Name: topics topics_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.topics
    ADD CONSTRAINT topics_pkey PRIMARY KEY (id);


--
-- Name: topics topics_value_key; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.topics
    ADD CONSTRAINT topics_value_key UNIQUE (value);


--
-- Name: tracking tracking_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.tracking
    ADD CONSTRAINT tracking_pkey PRIMARY KEY (id);


--
-- Name: unlocks unlocks_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.unlocks
    ADD CONSTRAINT unlocks_pkey PRIMARY KEY (id);


--
-- Name: user_sessions user_sessions_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.user_sessions
    ADD CONSTRAINT user_sessions_pkey PRIMARY KEY (id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_participant_token_key; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.users
    ADD CONSTRAINT users_participant_token_key UNIQUE (participant_token);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: idx_session_activity_session_date; Type: INDEX; Schema: ctfzone; Owner: -
--

CREATE INDEX idx_session_activity_session_date ON ctfzone.session_activity USING btree (session_id, date);


--
-- Name: idx_session_activity_token_date; Type: INDEX; Schema: ctfzone; Owner: -
--

CREATE INDEX idx_session_activity_token_date ON ctfzone.session_activity USING btree (api_token_id, date);


--
-- Name: idx_session_activity_user_date; Type: INDEX; Schema: ctfzone; Owner: -
--

CREATE INDEX idx_session_activity_user_date ON ctfzone.session_activity USING btree (user_id, date);


--
-- Name: idx_user_sessions_user_active; Type: INDEX; Schema: ctfzone; Owner: -
--

CREATE INDEX idx_user_sessions_user_active ON ctfzone.user_sessions USING btree (user_id, revoked_at, last_seen);


--
-- Name: awards awards_team_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.awards
    ADD CONSTRAINT awards_team_id_fkey FOREIGN KEY (team_id) REFERENCES ctfzone.teams(id) ON DELETE CASCADE;


--
-- Name: awards awards_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.awards
    ADD CONSTRAINT awards_user_id_fkey FOREIGN KEY (user_id) REFERENCES ctfzone.users(id) ON DELETE CASCADE;


--
-- Name: challenge_topics challenge_topics_challenge_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.challenge_topics
    ADD CONSTRAINT challenge_topics_challenge_id_fkey FOREIGN KEY (challenge_id) REFERENCES ctfzone.challenges(id) ON DELETE CASCADE;


--
-- Name: challenge_topics challenge_topics_topic_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.challenge_topics
    ADD CONSTRAINT challenge_topics_topic_id_fkey FOREIGN KEY (topic_id) REFERENCES ctfzone.topics(id) ON DELETE CASCADE;


--
-- Name: challenges challenges_next_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.challenges
    ADD CONSTRAINT challenges_next_id_fkey FOREIGN KEY (next_id) REFERENCES ctfzone.challenges(id) ON DELETE SET NULL;


--
-- Name: comments comments_author_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.comments
    ADD CONSTRAINT comments_author_id_fkey FOREIGN KEY (author_id) REFERENCES ctfzone.users(id) ON DELETE CASCADE;


--
-- Name: comments comments_challenge_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.comments
    ADD CONSTRAINT comments_challenge_id_fkey FOREIGN KEY (challenge_id) REFERENCES ctfzone.challenges(id) ON DELETE CASCADE;


--
-- Name: comments comments_page_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.comments
    ADD CONSTRAINT comments_page_id_fkey FOREIGN KEY (page_id) REFERENCES ctfzone.pages(id) ON DELETE CASCADE;


--
-- Name: comments comments_team_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.comments
    ADD CONSTRAINT comments_team_id_fkey FOREIGN KEY (team_id) REFERENCES ctfzone.teams(id) ON DELETE CASCADE;


--
-- Name: comments comments_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.comments
    ADD CONSTRAINT comments_user_id_fkey FOREIGN KEY (user_id) REFERENCES ctfzone.users(id) ON DELETE CASCADE;


--
-- Name: dynamic_challenge dynamic_challenge_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.dynamic_challenge
    ADD CONSTRAINT dynamic_challenge_id_fkey FOREIGN KEY (id) REFERENCES ctfzone.challenges(id) ON DELETE CASCADE;


--
-- Name: field_entries field_entries_field_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.field_entries
    ADD CONSTRAINT field_entries_field_id_fkey FOREIGN KEY (field_id) REFERENCES ctfzone.fields(id) ON DELETE CASCADE;


--
-- Name: field_entries field_entries_team_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.field_entries
    ADD CONSTRAINT field_entries_team_id_fkey FOREIGN KEY (team_id) REFERENCES ctfzone.teams(id) ON DELETE CASCADE;


--
-- Name: field_entries field_entries_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.field_entries
    ADD CONSTRAINT field_entries_user_id_fkey FOREIGN KEY (user_id) REFERENCES ctfzone.users(id) ON DELETE CASCADE;


--
-- Name: files files_challenge_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.files
    ADD CONSTRAINT files_challenge_id_fkey FOREIGN KEY (challenge_id) REFERENCES ctfzone.challenges(id) ON DELETE CASCADE;


--
-- Name: files files_page_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.files
    ADD CONSTRAINT files_page_id_fkey FOREIGN KEY (page_id) REFERENCES ctfzone.pages(id);


--
-- Name: files files_solution_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.files
    ADD CONSTRAINT files_solution_id_fkey FOREIGN KEY (solution_id) REFERENCES ctfzone.solutions(id);


--
-- Name: flags flags_challenge_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.flags
    ADD CONSTRAINT flags_challenge_id_fkey FOREIGN KEY (challenge_id) REFERENCES ctfzone.challenges(id) ON DELETE CASCADE;


--
-- Name: hints hints_challenge_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.hints
    ADD CONSTRAINT hints_challenge_id_fkey FOREIGN KEY (challenge_id) REFERENCES ctfzone.challenges(id) ON DELETE CASCADE;


--
-- Name: notifications notifications_team_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.notifications
    ADD CONSTRAINT notifications_team_id_fkey FOREIGN KEY (team_id) REFERENCES ctfzone.teams(id);


--
-- Name: notifications notifications_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.notifications
    ADD CONSTRAINT notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES ctfzone.users(id);


--
-- Name: ratings ratings_challenge_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.ratings
    ADD CONSTRAINT ratings_challenge_id_fkey FOREIGN KEY (challenge_id) REFERENCES ctfzone.challenges(id) ON DELETE CASCADE;


--
-- Name: ratings ratings_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.ratings
    ADD CONSTRAINT ratings_user_id_fkey FOREIGN KEY (user_id) REFERENCES ctfzone.users(id) ON DELETE CASCADE;


--
-- Name: session_activity session_activity_api_token_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.session_activity
    ADD CONSTRAINT session_activity_api_token_id_fkey FOREIGN KEY (api_token_id) REFERENCES ctfzone.tokens(id) ON DELETE SET NULL;


--
-- Name: session_activity session_activity_session_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.session_activity
    ADD CONSTRAINT session_activity_session_id_fkey FOREIGN KEY (session_id) REFERENCES ctfzone.user_sessions(id) ON DELETE SET NULL;


--
-- Name: session_activity session_activity_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.session_activity
    ADD CONSTRAINT session_activity_user_id_fkey FOREIGN KEY (user_id) REFERENCES ctfzone.users(id) ON DELETE CASCADE;


--
-- Name: solutions solutions_challenge_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.solutions
    ADD CONSTRAINT solutions_challenge_id_fkey FOREIGN KEY (challenge_id) REFERENCES ctfzone.challenges(id) ON DELETE CASCADE;


--
-- Name: solves solves_challenge_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.solves
    ADD CONSTRAINT solves_challenge_id_fkey FOREIGN KEY (challenge_id) REFERENCES ctfzone.challenges(id) ON DELETE CASCADE;


--
-- Name: solves solves_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.solves
    ADD CONSTRAINT solves_id_fkey FOREIGN KEY (id) REFERENCES ctfzone.submissions(id) ON DELETE CASCADE;


--
-- Name: solves solves_team_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.solves
    ADD CONSTRAINT solves_team_id_fkey FOREIGN KEY (team_id) REFERENCES ctfzone.teams(id) ON DELETE CASCADE;


--
-- Name: solves solves_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.solves
    ADD CONSTRAINT solves_user_id_fkey FOREIGN KEY (user_id) REFERENCES ctfzone.users(id) ON DELETE CASCADE;


--
-- Name: submissions submissions_challenge_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.submissions
    ADD CONSTRAINT submissions_challenge_id_fkey FOREIGN KEY (challenge_id) REFERENCES ctfzone.challenges(id) ON DELETE CASCADE;


--
-- Name: submissions submissions_team_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.submissions
    ADD CONSTRAINT submissions_team_id_fkey FOREIGN KEY (team_id) REFERENCES ctfzone.teams(id) ON DELETE CASCADE;


--
-- Name: submissions submissions_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.submissions
    ADD CONSTRAINT submissions_user_id_fkey FOREIGN KEY (user_id) REFERENCES ctfzone.users(id) ON DELETE CASCADE;


--
-- Name: tags tags_challenge_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.tags
    ADD CONSTRAINT tags_challenge_id_fkey FOREIGN KEY (challenge_id) REFERENCES ctfzone.challenges(id) ON DELETE CASCADE;


--
-- Name: teams teams_bracket_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.teams
    ADD CONSTRAINT teams_bracket_id_fkey FOREIGN KEY (bracket_id) REFERENCES ctfzone.brackets(id) ON DELETE SET NULL;


--
-- Name: teams teams_captain_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.teams
    ADD CONSTRAINT teams_captain_id_fkey FOREIGN KEY (captain_id) REFERENCES ctfzone.users(id) ON DELETE SET NULL;


--
-- Name: tokens tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.tokens
    ADD CONSTRAINT tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES ctfzone.users(id) ON DELETE CASCADE;


--
-- Name: tracking tracking_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.tracking
    ADD CONSTRAINT tracking_user_id_fkey FOREIGN KEY (user_id) REFERENCES ctfzone.users(id) ON DELETE CASCADE;


--
-- Name: unlocks unlocks_team_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.unlocks
    ADD CONSTRAINT unlocks_team_id_fkey FOREIGN KEY (team_id) REFERENCES ctfzone.teams(id) ON DELETE CASCADE;


--
-- Name: unlocks unlocks_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.unlocks
    ADD CONSTRAINT unlocks_user_id_fkey FOREIGN KEY (user_id) REFERENCES ctfzone.users(id) ON DELETE CASCADE;


--
-- Name: user_sessions user_sessions_revoked_by_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.user_sessions
    ADD CONSTRAINT user_sessions_revoked_by_user_id_fkey FOREIGN KEY (revoked_by_user_id) REFERENCES ctfzone.users(id) ON DELETE SET NULL;


--
-- Name: user_sessions user_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.user_sessions
    ADD CONSTRAINT user_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES ctfzone.users(id) ON DELETE CASCADE;


--
-- Name: users users_bracket_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.users
    ADD CONSTRAINT users_bracket_id_fkey FOREIGN KEY (bracket_id) REFERENCES ctfzone.brackets(id) ON DELETE SET NULL;


--
-- Name: users users_team_id_fkey; Type: FK CONSTRAINT; Schema: ctfzone; Owner: -
--

ALTER TABLE ONLY ctfzone.users
    ADD CONSTRAINT users_team_id_fkey FOREIGN KEY (team_id) REFERENCES ctfzone.teams(id);


--
-- PostgreSQL database dump complete
--
