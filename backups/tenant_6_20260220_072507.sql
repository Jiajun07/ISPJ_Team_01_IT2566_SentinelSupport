--
-- PostgreSQL database dump
--

\restrict pkiBQQd7hqLHGz4NhqEtThsEqQOdFoESp5DdVl7BiN6IELLvhOgatMKLxGdlJKB

-- Dumped from database version 17.6
-- Dumped by pg_dump version 17.6

-- Started on 2026-02-20 07:25:08

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

DROP POLICY IF EXISTS tenant_6_rls_users ON tenant_6.users;
DROP POLICY IF EXISTS tenant_6_rls_documents ON tenant_6.documents;
DROP POLICY IF EXISTS tenant_6_rls_audit ON tenant_6.audit_logs;
DROP POLICY IF EXISTS tenant_6_retention_audit ON tenant_6.audit_logs;
DROP POLICY IF EXISTS tenant_6_dlp_restrict ON tenant_6.documents;
ALTER TABLE IF EXISTS ONLY tenant_6.documents DROP CONSTRAINT IF EXISTS documents_owner_user_id_fkey;
ALTER TABLE IF EXISTS ONLY tenant_6.audit_logs DROP CONSTRAINT IF EXISTS audit_logs_user_id_fkey;
DROP INDEX IF EXISTS tenant_6.idx_versions_document;
DROP INDEX IF EXISTS tenant_6.idx_sharing_recipient;
DROP INDEX IF EXISTS tenant_6.idx_sharing_document;
DROP INDEX IF EXISTS tenant_6.idx_share_links_token;
DROP INDEX IF EXISTS tenant_6.idx_share_links_document;
DROP INDEX IF EXISTS tenant_6.idx_files_owner;
DROP INDEX IF EXISTS tenant_6.idx_files_document_id;
DROP INDEX IF EXISTS tenant_6.idx_files_current;
DROP INDEX IF EXISTS tenant_6.idx_exchange_status;
DROP INDEX IF EXISTS tenant_6.idx_exchange_id;
DROP INDEX IF EXISTS tenant_6.idx_activity_document;
DROP INDEX IF EXISTS tenant_6.idx_activity_action;
ALTER TABLE IF EXISTS ONLY tenant_6.users DROP CONSTRAINT IF EXISTS users_pkey;
ALTER TABLE IF EXISTS ONLY tenant_6.users DROP CONSTRAINT IF EXISTS users_email_key;
ALTER TABLE IF EXISTS ONLY tenant_6.sharing DROP CONSTRAINT IF EXISTS sharing_pkey;
ALTER TABLE IF EXISTS ONLY tenant_6.sharing DROP CONSTRAINT IF EXISTS sharing_document_id_shared_with_email_key;
ALTER TABLE IF EXISTS ONLY tenant_6.sharing_activity DROP CONSTRAINT IF EXISTS sharing_activity_pkey;
ALTER TABLE IF EXISTS ONLY tenant_6.key_exchanges DROP CONSTRAINT IF EXISTS key_exchanges_pkey;
ALTER TABLE IF EXISTS ONLY tenant_6.key_exchanges DROP CONSTRAINT IF EXISTS key_exchanges_exchange_id_key;
ALTER TABLE IF EXISTS ONLY tenant_6.files DROP CONSTRAINT IF EXISTS files_pkey;
ALTER TABLE IF EXISTS ONLY tenant_6.file_versions DROP CONSTRAINT IF EXISTS file_versions_pkey;
ALTER TABLE IF EXISTS ONLY tenant_6.file_versions DROP CONSTRAINT IF EXISTS file_versions_document_id_version_number_key;
ALTER TABLE IF EXISTS ONLY tenant_6.file_sharing_links DROP CONSTRAINT IF EXISTS file_sharing_links_share_token_key;
ALTER TABLE IF EXISTS ONLY tenant_6.file_sharing_links DROP CONSTRAINT IF EXISTS file_sharing_links_pkey;
ALTER TABLE IF EXISTS ONLY tenant_6.documents DROP CONSTRAINT IF EXISTS documents_pkey;
ALTER TABLE IF EXISTS ONLY tenant_6.audit_logs DROP CONSTRAINT IF EXISTS audit_logs_pkey;
ALTER TABLE IF EXISTS tenant_6.users ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS tenant_6.sharing_activity ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS tenant_6.sharing ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS tenant_6.key_exchanges ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS tenant_6.files ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS tenant_6.file_versions ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS tenant_6.file_sharing_links ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS tenant_6.documents ALTER COLUMN id DROP DEFAULT;
ALTER TABLE IF EXISTS tenant_6.audit_logs ALTER COLUMN id DROP DEFAULT;
DROP SEQUENCE IF EXISTS tenant_6.users_id_seq;
DROP TABLE IF EXISTS tenant_6.users;
DROP SEQUENCE IF EXISTS tenant_6.sharing_id_seq;
DROP SEQUENCE IF EXISTS tenant_6.sharing_activity_id_seq;
DROP TABLE IF EXISTS tenant_6.sharing_activity;
DROP TABLE IF EXISTS tenant_6.sharing;
DROP SEQUENCE IF EXISTS tenant_6.key_exchanges_id_seq;
DROP TABLE IF EXISTS tenant_6.key_exchanges;
DROP SEQUENCE IF EXISTS tenant_6.files_id_seq;
DROP TABLE IF EXISTS tenant_6.files;
DROP SEQUENCE IF EXISTS tenant_6.file_versions_id_seq;
DROP TABLE IF EXISTS tenant_6.file_versions;
DROP SEQUENCE IF EXISTS tenant_6.file_sharing_links_id_seq;
DROP TABLE IF EXISTS tenant_6.file_sharing_links;
DROP SEQUENCE IF EXISTS tenant_6.documents_id_seq;
DROP TABLE IF EXISTS tenant_6.documents;
DROP SEQUENCE IF EXISTS tenant_6.audit_logs_id_seq;
DROP TABLE IF EXISTS tenant_6.audit_logs;
DROP SCHEMA IF EXISTS tenant_6;
--
-- TOC entry 139 (class 2615 OID 33405)
-- Name: tenant_6; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA tenant_6;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 500 (class 1259 OID 33406)
-- Name: audit_logs; Type: TABLE; Schema: tenant_6; Owner: -
--

CREATE TABLE tenant_6.audit_logs (
    id integer NOT NULL,
    user_id integer,
    action character varying(100) NOT NULL,
    target_type character varying(50),
    target_id integer,
    details text,
    created_at timestamp without time zone DEFAULT now()
);


--
-- TOC entry 501 (class 1259 OID 33412)
-- Name: audit_logs_id_seq; Type: SEQUENCE; Schema: tenant_6; Owner: -
--

CREATE SEQUENCE tenant_6.audit_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 4232 (class 0 OID 0)
-- Dependencies: 501
-- Name: audit_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: tenant_6; Owner: -
--

ALTER SEQUENCE tenant_6.audit_logs_id_seq OWNED BY tenant_6.audit_logs.id;


--
-- TOC entry 502 (class 1259 OID 33413)
-- Name: documents; Type: TABLE; Schema: tenant_6; Owner: -
--

CREATE TABLE tenant_6.documents (
    id integer NOT NULL,
    owner_user_id integer,
    file_path text NOT NULL,
    classification character varying(50) NOT NULL,
    version integer DEFAULT 1,
    created_at timestamp without time zone DEFAULT now()
);


--
-- TOC entry 503 (class 1259 OID 33420)
-- Name: documents_id_seq; Type: SEQUENCE; Schema: tenant_6; Owner: -
--

CREATE SEQUENCE tenant_6.documents_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 4233 (class 0 OID 0)
-- Dependencies: 503
-- Name: documents_id_seq; Type: SEQUENCE OWNED BY; Schema: tenant_6; Owner: -
--

ALTER SEQUENCE tenant_6.documents_id_seq OWNED BY tenant_6.documents.id;


--
-- TOC entry 504 (class 1259 OID 33421)
-- Name: file_sharing_links; Type: TABLE; Schema: tenant_6; Owner: -
--

CREATE TABLE tenant_6.file_sharing_links (
    id integer NOT NULL,
    document_id character varying(50) NOT NULL,
    file_name character varying(255) NOT NULL,
    share_token character varying(255) NOT NULL,
    password_hash character varying(255),
    require_key_exchange boolean DEFAULT false,
    exchange_id character varying(255),
    created_by character varying(255) NOT NULL,
    is_active boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT now(),
    expires_at timestamp without time zone,
    last_accessed timestamp without time zone,
    access_count integer DEFAULT 0
);


--
-- TOC entry 505 (class 1259 OID 33430)
-- Name: file_sharing_links_id_seq; Type: SEQUENCE; Schema: tenant_6; Owner: -
--

CREATE SEQUENCE tenant_6.file_sharing_links_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 4234 (class 0 OID 0)
-- Dependencies: 505
-- Name: file_sharing_links_id_seq; Type: SEQUENCE OWNED BY; Schema: tenant_6; Owner: -
--

ALTER SEQUENCE tenant_6.file_sharing_links_id_seq OWNED BY tenant_6.file_sharing_links.id;


--
-- TOC entry 506 (class 1259 OID 33431)
-- Name: file_versions; Type: TABLE; Schema: tenant_6; Owner: -
--

CREATE TABLE tenant_6.file_versions (
    id integer NOT NULL,
    document_id character varying(50) NOT NULL,
    version_number integer NOT NULL,
    file_name character varying(255) NOT NULL,
    file_data bytea NOT NULL,
    file_size bigint NOT NULL,
    file_hash character varying(64) NOT NULL,
    mime_type character varying(100),
    uploaded_by character varying(255) NOT NULL,
    uploaded_at timestamp without time zone DEFAULT now(),
    is_current boolean DEFAULT false
);


--
-- TOC entry 507 (class 1259 OID 33438)
-- Name: file_versions_id_seq; Type: SEQUENCE; Schema: tenant_6; Owner: -
--

CREATE SEQUENCE tenant_6.file_versions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 4235 (class 0 OID 0)
-- Dependencies: 507
-- Name: file_versions_id_seq; Type: SEQUENCE OWNED BY; Schema: tenant_6; Owner: -
--

ALTER SEQUENCE tenant_6.file_versions_id_seq OWNED BY tenant_6.file_versions.id;


--
-- TOC entry 508 (class 1259 OID 33439)
-- Name: files; Type: TABLE; Schema: tenant_6; Owner: -
--

CREATE TABLE tenant_6.files (
    id integer NOT NULL,
    document_id character varying(50) NOT NULL,
    file_name character varying(255) NOT NULL,
    owner_user_id integer NOT NULL,
    owner_email character varying(255) NOT NULL,
    file_data bytea NOT NULL,
    file_size bigint NOT NULL,
    file_hash character varying(64) NOT NULL,
    mime_type character varying(100),
    sensitivity character varying(50) DEFAULT 'Public'::character varying,
    classification character varying(50),
    risk_level character varying(50),
    notes text,
    is_current_version boolean DEFAULT true,
    is_deleted boolean DEFAULT false,
    deleted_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- TOC entry 509 (class 1259 OID 33449)
-- Name: files_id_seq; Type: SEQUENCE; Schema: tenant_6; Owner: -
--

CREATE SEQUENCE tenant_6.files_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 4236 (class 0 OID 0)
-- Dependencies: 509
-- Name: files_id_seq; Type: SEQUENCE OWNED BY; Schema: tenant_6; Owner: -
--

ALTER SEQUENCE tenant_6.files_id_seq OWNED BY tenant_6.files.id;


--
-- TOC entry 510 (class 1259 OID 33450)
-- Name: key_exchanges; Type: TABLE; Schema: tenant_6; Owner: -
--

CREATE TABLE tenant_6.key_exchanges (
    id integer NOT NULL,
    exchange_id character varying(255) NOT NULL,
    sharer_email character varying(255) NOT NULL,
    recipient_email character varying(255) NOT NULL,
    document_id character varying(50) NOT NULL,
    file_name character varying(255) NOT NULL,
    sharer_public_key text,
    recipient_public_key text,
    sharer_fingerprint character varying(64),
    recipient_fingerprint character varying(64),
    status character varying(50) DEFAULT 'pending'::character varying,
    sharer_verified boolean DEFAULT false,
    recipient_verified boolean DEFAULT false,
    recipient_confirmed boolean DEFAULT false,
    created_at timestamp without time zone DEFAULT now(),
    expires_at timestamp without time zone,
    verified_at timestamp without time zone
);


--
-- TOC entry 511 (class 1259 OID 33460)
-- Name: key_exchanges_id_seq; Type: SEQUENCE; Schema: tenant_6; Owner: -
--

CREATE SEQUENCE tenant_6.key_exchanges_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 4237 (class 0 OID 0)
-- Dependencies: 511
-- Name: key_exchanges_id_seq; Type: SEQUENCE OWNED BY; Schema: tenant_6; Owner: -
--

ALTER SEQUENCE tenant_6.key_exchanges_id_seq OWNED BY tenant_6.key_exchanges.id;


--
-- TOC entry 512 (class 1259 OID 33461)
-- Name: sharing; Type: TABLE; Schema: tenant_6; Owner: -
--

CREATE TABLE tenant_6.sharing (
    id integer NOT NULL,
    document_id character varying(50) NOT NULL,
    file_name character varying(255) NOT NULL,
    shared_with_email character varying(255) NOT NULL,
    shared_by_email character varying(255) NOT NULL,
    access_level character varying(50) DEFAULT 'view'::character varying,
    is_accepted boolean DEFAULT false,
    is_active boolean DEFAULT true,
    shared_at timestamp without time zone DEFAULT now(),
    expires_at timestamp without time zone,
    last_accessed timestamp without time zone,
    access_count integer DEFAULT 0
);


--
-- TOC entry 513 (class 1259 OID 33471)
-- Name: sharing_activity; Type: TABLE; Schema: tenant_6; Owner: -
--

CREATE TABLE tenant_6.sharing_activity (
    id integer NOT NULL,
    document_id character varying(50) NOT NULL,
    file_name character varying(255) NOT NULL,
    action character varying(50) NOT NULL,
    shared_with_email character varying(255),
    shared_via_link character varying(255),
    shared_by_email character varying(255) NOT NULL,
    ip_address character varying(50),
    user_agent character varying(255),
    activity_at timestamp without time zone DEFAULT now(),
    details jsonb
);


--
-- TOC entry 514 (class 1259 OID 33477)
-- Name: sharing_activity_id_seq; Type: SEQUENCE; Schema: tenant_6; Owner: -
--

CREATE SEQUENCE tenant_6.sharing_activity_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 4238 (class 0 OID 0)
-- Dependencies: 514
-- Name: sharing_activity_id_seq; Type: SEQUENCE OWNED BY; Schema: tenant_6; Owner: -
--

ALTER SEQUENCE tenant_6.sharing_activity_id_seq OWNED BY tenant_6.sharing_activity.id;


--
-- TOC entry 515 (class 1259 OID 33478)
-- Name: sharing_id_seq; Type: SEQUENCE; Schema: tenant_6; Owner: -
--

CREATE SEQUENCE tenant_6.sharing_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 4239 (class 0 OID 0)
-- Dependencies: 515
-- Name: sharing_id_seq; Type: SEQUENCE OWNED BY; Schema: tenant_6; Owner: -
--

ALTER SEQUENCE tenant_6.sharing_id_seq OWNED BY tenant_6.sharing.id;


--
-- TOC entry 516 (class 1259 OID 33479)
-- Name: users; Type: TABLE; Schema: tenant_6; Owner: -
--

CREATE TABLE tenant_6.users (
    id integer NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    role character varying(50) DEFAULT 'user'::character varying NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    usb_mfa_enabled boolean DEFAULT false
);


--
-- TOC entry 517 (class 1259 OID 33486)
-- Name: users_id_seq; Type: SEQUENCE; Schema: tenant_6; Owner: -
--

CREATE SEQUENCE tenant_6.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- TOC entry 4240 (class 0 OID 0)
-- Dependencies: 517
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: tenant_6; Owner: -
--

ALTER SEQUENCE tenant_6.users_id_seq OWNED BY tenant_6.users.id;


--
-- TOC entry 3976 (class 2604 OID 33487)
-- Name: audit_logs id; Type: DEFAULT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.audit_logs ALTER COLUMN id SET DEFAULT nextval('tenant_6.audit_logs_id_seq'::regclass);


--
-- TOC entry 3978 (class 2604 OID 33488)
-- Name: documents id; Type: DEFAULT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.documents ALTER COLUMN id SET DEFAULT nextval('tenant_6.documents_id_seq'::regclass);


--
-- TOC entry 3981 (class 2604 OID 33489)
-- Name: file_sharing_links id; Type: DEFAULT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.file_sharing_links ALTER COLUMN id SET DEFAULT nextval('tenant_6.file_sharing_links_id_seq'::regclass);


--
-- TOC entry 3986 (class 2604 OID 33490)
-- Name: file_versions id; Type: DEFAULT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.file_versions ALTER COLUMN id SET DEFAULT nextval('tenant_6.file_versions_id_seq'::regclass);


--
-- TOC entry 3989 (class 2604 OID 33491)
-- Name: files id; Type: DEFAULT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.files ALTER COLUMN id SET DEFAULT nextval('tenant_6.files_id_seq'::regclass);


--
-- TOC entry 3995 (class 2604 OID 33492)
-- Name: key_exchanges id; Type: DEFAULT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.key_exchanges ALTER COLUMN id SET DEFAULT nextval('tenant_6.key_exchanges_id_seq'::regclass);


--
-- TOC entry 4001 (class 2604 OID 33493)
-- Name: sharing id; Type: DEFAULT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.sharing ALTER COLUMN id SET DEFAULT nextval('tenant_6.sharing_id_seq'::regclass);


--
-- TOC entry 4007 (class 2604 OID 33494)
-- Name: sharing_activity id; Type: DEFAULT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.sharing_activity ALTER COLUMN id SET DEFAULT nextval('tenant_6.sharing_activity_id_seq'::regclass);


--
-- TOC entry 4009 (class 2604 OID 33495)
-- Name: users id; Type: DEFAULT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.users ALTER COLUMN id SET DEFAULT nextval('tenant_6.users_id_seq'::regclass);


--
-- TOC entry 4209 (class 0 OID 33406)
-- Dependencies: 500
-- Data for Name: audit_logs; Type: TABLE DATA; Schema: tenant_6; Owner: -
--

COPY tenant_6.audit_logs (id, user_id, action, target_type, target_id, details, created_at) FROM stdin;
\.


--
-- TOC entry 4211 (class 0 OID 33413)
-- Dependencies: 502
-- Data for Name: documents; Type: TABLE DATA; Schema: tenant_6; Owner: -
--

COPY tenant_6.documents (id, owner_user_id, file_path, classification, version, created_at) FROM stdin;
\.


--
-- TOC entry 4213 (class 0 OID 33421)
-- Dependencies: 504
-- Data for Name: file_sharing_links; Type: TABLE DATA; Schema: tenant_6; Owner: -
--

COPY tenant_6.file_sharing_links (id, document_id, file_name, share_token, password_hash, require_key_exchange, exchange_id, created_by, is_active, created_at, expires_at, last_accessed, access_count) FROM stdin;
\.


--
-- TOC entry 4215 (class 0 OID 33431)
-- Dependencies: 506
-- Data for Name: file_versions; Type: TABLE DATA; Schema: tenant_6; Owner: -
--

COPY tenant_6.file_versions (id, document_id, version_number, file_name, file_data, file_size, file_hash, mime_type, uploaded_by, uploaded_at, is_current) FROM stdin;
\.


--
-- TOC entry 4217 (class 0 OID 33439)
-- Dependencies: 508
-- Data for Name: files; Type: TABLE DATA; Schema: tenant_6; Owner: -
--

COPY tenant_6.files (id, document_id, file_name, owner_user_id, owner_email, file_data, file_size, file_hash, mime_type, sensitivity, classification, risk_level, notes, is_current_version, is_deleted, deleted_at, created_at, updated_at) FROM stdin;
\.


--
-- TOC entry 4219 (class 0 OID 33450)
-- Dependencies: 510
-- Data for Name: key_exchanges; Type: TABLE DATA; Schema: tenant_6; Owner: -
--

COPY tenant_6.key_exchanges (id, exchange_id, sharer_email, recipient_email, document_id, file_name, sharer_public_key, recipient_public_key, sharer_fingerprint, recipient_fingerprint, status, sharer_verified, recipient_verified, recipient_confirmed, created_at, expires_at, verified_at) FROM stdin;
\.


--
-- TOC entry 4221 (class 0 OID 33461)
-- Dependencies: 512
-- Data for Name: sharing; Type: TABLE DATA; Schema: tenant_6; Owner: -
--

COPY tenant_6.sharing (id, document_id, file_name, shared_with_email, shared_by_email, access_level, is_accepted, is_active, shared_at, expires_at, last_accessed, access_count) FROM stdin;
\.


--
-- TOC entry 4222 (class 0 OID 33471)
-- Dependencies: 513
-- Data for Name: sharing_activity; Type: TABLE DATA; Schema: tenant_6; Owner: -
--

COPY tenant_6.sharing_activity (id, document_id, file_name, action, shared_with_email, shared_via_link, shared_by_email, ip_address, user_agent, activity_at, details) FROM stdin;
\.


--
-- TOC entry 4225 (class 0 OID 33479)
-- Dependencies: 516
-- Data for Name: users; Type: TABLE DATA; Schema: tenant_6; Owner: -
--

COPY tenant_6.users (id, email, password_hash, role, created_at, usb_mfa_enabled) FROM stdin;
1	Jjfong@gmail.com	$2b$12$eYXK/NybAXl.41/lHXOxOuWiUWXGmEA3/VDRiQUMSsZaGTT0IVmI6	admin	2026-02-06 01:10:12.311332	f
\.


--
-- TOC entry 4241 (class 0 OID 0)
-- Dependencies: 501
-- Name: audit_logs_id_seq; Type: SEQUENCE SET; Schema: tenant_6; Owner: -
--

SELECT pg_catalog.setval('tenant_6.audit_logs_id_seq', 1, false);


--
-- TOC entry 4242 (class 0 OID 0)
-- Dependencies: 503
-- Name: documents_id_seq; Type: SEQUENCE SET; Schema: tenant_6; Owner: -
--

SELECT pg_catalog.setval('tenant_6.documents_id_seq', 1, false);


--
-- TOC entry 4243 (class 0 OID 0)
-- Dependencies: 505
-- Name: file_sharing_links_id_seq; Type: SEQUENCE SET; Schema: tenant_6; Owner: -
--

SELECT pg_catalog.setval('tenant_6.file_sharing_links_id_seq', 1, false);


--
-- TOC entry 4244 (class 0 OID 0)
-- Dependencies: 507
-- Name: file_versions_id_seq; Type: SEQUENCE SET; Schema: tenant_6; Owner: -
--

SELECT pg_catalog.setval('tenant_6.file_versions_id_seq', 1, false);


--
-- TOC entry 4245 (class 0 OID 0)
-- Dependencies: 509
-- Name: files_id_seq; Type: SEQUENCE SET; Schema: tenant_6; Owner: -
--

SELECT pg_catalog.setval('tenant_6.files_id_seq', 1, false);


--
-- TOC entry 4246 (class 0 OID 0)
-- Dependencies: 511
-- Name: key_exchanges_id_seq; Type: SEQUENCE SET; Schema: tenant_6; Owner: -
--

SELECT pg_catalog.setval('tenant_6.key_exchanges_id_seq', 1, false);


--
-- TOC entry 4247 (class 0 OID 0)
-- Dependencies: 514
-- Name: sharing_activity_id_seq; Type: SEQUENCE SET; Schema: tenant_6; Owner: -
--

SELECT pg_catalog.setval('tenant_6.sharing_activity_id_seq', 1, false);


--
-- TOC entry 4248 (class 0 OID 0)
-- Dependencies: 515
-- Name: sharing_id_seq; Type: SEQUENCE SET; Schema: tenant_6; Owner: -
--

SELECT pg_catalog.setval('tenant_6.sharing_id_seq', 1, false);


--
-- TOC entry 4249 (class 0 OID 0)
-- Dependencies: 517
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: tenant_6; Owner: -
--

SELECT pg_catalog.setval('tenant_6.users_id_seq', 1, true);


--
-- TOC entry 4014 (class 2606 OID 33497)
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- TOC entry 4016 (class 2606 OID 33499)
-- Name: documents documents_pkey; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.documents
    ADD CONSTRAINT documents_pkey PRIMARY KEY (id);


--
-- TOC entry 4018 (class 2606 OID 33501)
-- Name: file_sharing_links file_sharing_links_pkey; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.file_sharing_links
    ADD CONSTRAINT file_sharing_links_pkey PRIMARY KEY (id);


--
-- TOC entry 4020 (class 2606 OID 33503)
-- Name: file_sharing_links file_sharing_links_share_token_key; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.file_sharing_links
    ADD CONSTRAINT file_sharing_links_share_token_key UNIQUE (share_token);


--
-- TOC entry 4024 (class 2606 OID 33505)
-- Name: file_versions file_versions_document_id_version_number_key; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.file_versions
    ADD CONSTRAINT file_versions_document_id_version_number_key UNIQUE (document_id, version_number);


--
-- TOC entry 4026 (class 2606 OID 33507)
-- Name: file_versions file_versions_pkey; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.file_versions
    ADD CONSTRAINT file_versions_pkey PRIMARY KEY (id);


--
-- TOC entry 4029 (class 2606 OID 33509)
-- Name: files files_pkey; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.files
    ADD CONSTRAINT files_pkey PRIMARY KEY (id);


--
-- TOC entry 4036 (class 2606 OID 33511)
-- Name: key_exchanges key_exchanges_exchange_id_key; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.key_exchanges
    ADD CONSTRAINT key_exchanges_exchange_id_key UNIQUE (exchange_id);


--
-- TOC entry 4038 (class 2606 OID 33513)
-- Name: key_exchanges key_exchanges_pkey; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.key_exchanges
    ADD CONSTRAINT key_exchanges_pkey PRIMARY KEY (id);


--
-- TOC entry 4048 (class 2606 OID 33515)
-- Name: sharing_activity sharing_activity_pkey; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.sharing_activity
    ADD CONSTRAINT sharing_activity_pkey PRIMARY KEY (id);


--
-- TOC entry 4042 (class 2606 OID 33517)
-- Name: sharing sharing_document_id_shared_with_email_key; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.sharing
    ADD CONSTRAINT sharing_document_id_shared_with_email_key UNIQUE (document_id, shared_with_email);


--
-- TOC entry 4044 (class 2606 OID 33519)
-- Name: sharing sharing_pkey; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.sharing
    ADD CONSTRAINT sharing_pkey PRIMARY KEY (id);


--
-- TOC entry 4050 (class 2606 OID 33521)
-- Name: users users_email_key; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- TOC entry 4052 (class 2606 OID 33523)
-- Name: users users_pkey; Type: CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- TOC entry 4045 (class 1259 OID 33524)
-- Name: idx_activity_action; Type: INDEX; Schema: tenant_6; Owner: -
--

CREATE INDEX idx_activity_action ON tenant_6.sharing_activity USING btree (action);


--
-- TOC entry 4046 (class 1259 OID 33525)
-- Name: idx_activity_document; Type: INDEX; Schema: tenant_6; Owner: -
--

CREATE INDEX idx_activity_document ON tenant_6.sharing_activity USING btree (document_id);


--
-- TOC entry 4033 (class 1259 OID 33526)
-- Name: idx_exchange_id; Type: INDEX; Schema: tenant_6; Owner: -
--

CREATE INDEX idx_exchange_id ON tenant_6.key_exchanges USING btree (exchange_id);


--
-- TOC entry 4034 (class 1259 OID 33527)
-- Name: idx_exchange_status; Type: INDEX; Schema: tenant_6; Owner: -
--

CREATE INDEX idx_exchange_status ON tenant_6.key_exchanges USING btree (status);


--
-- TOC entry 4030 (class 1259 OID 33528)
-- Name: idx_files_current; Type: INDEX; Schema: tenant_6; Owner: -
--

CREATE INDEX idx_files_current ON tenant_6.files USING btree (is_current_version);


--
-- TOC entry 4031 (class 1259 OID 33529)
-- Name: idx_files_document_id; Type: INDEX; Schema: tenant_6; Owner: -
--

CREATE INDEX idx_files_document_id ON tenant_6.files USING btree (document_id);


--
-- TOC entry 4032 (class 1259 OID 33530)
-- Name: idx_files_owner; Type: INDEX; Schema: tenant_6; Owner: -
--

CREATE INDEX idx_files_owner ON tenant_6.files USING btree (owner_user_id);


--
-- TOC entry 4021 (class 1259 OID 33531)
-- Name: idx_share_links_document; Type: INDEX; Schema: tenant_6; Owner: -
--

CREATE INDEX idx_share_links_document ON tenant_6.file_sharing_links USING btree (document_id);


--
-- TOC entry 4022 (class 1259 OID 33532)
-- Name: idx_share_links_token; Type: INDEX; Schema: tenant_6; Owner: -
--

CREATE INDEX idx_share_links_token ON tenant_6.file_sharing_links USING btree (share_token);


--
-- TOC entry 4039 (class 1259 OID 33533)
-- Name: idx_sharing_document; Type: INDEX; Schema: tenant_6; Owner: -
--

CREATE INDEX idx_sharing_document ON tenant_6.sharing USING btree (document_id);


--
-- TOC entry 4040 (class 1259 OID 33534)
-- Name: idx_sharing_recipient; Type: INDEX; Schema: tenant_6; Owner: -
--

CREATE INDEX idx_sharing_recipient ON tenant_6.sharing USING btree (shared_with_email);


--
-- TOC entry 4027 (class 1259 OID 33535)
-- Name: idx_versions_document; Type: INDEX; Schema: tenant_6; Owner: -
--

CREATE INDEX idx_versions_document ON tenant_6.file_versions USING btree (document_id);


--
-- TOC entry 4053 (class 2606 OID 33536)
-- Name: audit_logs audit_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.audit_logs
    ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES tenant_6.users(id);


--
-- TOC entry 4054 (class 2606 OID 33541)
-- Name: documents documents_owner_user_id_fkey; Type: FK CONSTRAINT; Schema: tenant_6; Owner: -
--

ALTER TABLE ONLY tenant_6.documents
    ADD CONSTRAINT documents_owner_user_id_fkey FOREIGN KEY (owner_user_id) REFERENCES tenant_6.users(id);


--
-- TOC entry 4203 (class 3256 OID 33546)
-- Name: documents tenant_6_dlp_restrict; Type: POLICY; Schema: tenant_6; Owner: -
--

CREATE POLICY tenant_6_dlp_restrict ON tenant_6.documents FOR SELECT USING (((classification)::text <> 'HIGHLY_CONFIDENTIAL'::text));


--
-- TOC entry 4204 (class 3256 OID 33547)
-- Name: audit_logs tenant_6_retention_audit; Type: POLICY; Schema: tenant_6; Owner: -
--

CREATE POLICY tenant_6_retention_audit ON tenant_6.audit_logs USING ((created_at > (now() - '365 days'::interval)));


--
-- TOC entry 4205 (class 3256 OID 33548)
-- Name: audit_logs tenant_6_rls_audit; Type: POLICY; Schema: tenant_6; Owner: -
--

CREATE POLICY tenant_6_rls_audit ON tenant_6.audit_logs USING (true);


--
-- TOC entry 4206 (class 3256 OID 33549)
-- Name: documents tenant_6_rls_documents; Type: POLICY; Schema: tenant_6; Owner: -
--

CREATE POLICY tenant_6_rls_documents ON tenant_6.documents USING (true);


--
-- TOC entry 4207 (class 3256 OID 33550)
-- Name: users tenant_6_rls_users; Type: POLICY; Schema: tenant_6; Owner: -
--

CREATE POLICY tenant_6_rls_users ON tenant_6.users USING (true);


-- Completed on 2026-02-20 07:25:15

--
-- PostgreSQL database dump complete
--

\unrestrict pkiBQQd7hqLHGz4NhqEtThsEqQOdFoESp5DdVl7BiN6IELLvhOgatMKLxGdlJKB

