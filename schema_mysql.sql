-- Smart Bug Lifecycle, Root Cause Analysis and Release Management System
-- Production schema (MySQL 8+). For local dev, app.py auto-creates an
-- equivalent SQLite schema (see app/db.py) so the app runs with zero setup.

CREATE DATABASE IF NOT EXISTS sbl_system CHARACTER SET utf8mb4;
USE sbl_system;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('Admin','Manager','Developer','Tester') NOT NULL DEFAULT 'Tester',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE projects (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    description TEXT,
    created_by INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE project_members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    project_id INT NOT NULL,
    user_id INT NOT NULL,
    project_role VARCHAR(50),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (project_id, user_id)
);

CREATE TABLE bugs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    project_id INT NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    reproduction_steps TEXT,
    severity ENUM('Low','Medium','High','Critical') DEFAULT 'Medium',
    priority ENUM('Low','Medium','High','Urgent') DEFAULT 'Medium',
    status ENUM('New','Assigned','In Progress','Fixed','Testing','Closed') DEFAULT 'New',
    reported_by INT,
    assigned_to INT,
    attachment_path VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (reported_by) REFERENCES users(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id)
);

CREATE TABLE bug_comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    bug_id INT NOT NULL,
    user_id INT NOT NULL,
    comment TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bug_id) REFERENCES bugs(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE bug_activity (
    id INT AUTO_INCREMENT PRIMARY KEY,
    bug_id INT NOT NULL,
    user_id INT,
    action VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bug_id) REFERENCES bugs(id) ON DELETE CASCADE
);

CREATE TABLE root_cause_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    bug_id INT NOT NULL,
    category VARCHAR(100) NOT NULL,
    root_cause TEXT NOT NULL,
    preventive_action TEXT,
    technical_recommendation TEXT,
    created_by INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bug_id) REFERENCES bugs(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE knowledge_base (
    id INT AUTO_INCREMENT PRIMARY KEY,
    bug_id INT,
    title VARCHAR(200) NOT NULL,
    problem_summary TEXT,
    solution TEXT NOT NULL,
    tags VARCHAR(255),
    created_by INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bug_id) REFERENCES bugs(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE releases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    project_id INT NOT NULL,
    version_number VARCHAR(50) NOT NULL,
    release_type ENUM('Major','Minor','Patch','Hotfix') DEFAULT 'Minor',
    release_notes TEXT,
    status ENUM('Planned','In Progress','Released','Rolled Back') DEFAULT 'Planned',
    released_at DATETIME NULL,
    created_by INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE release_bugs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    release_id INT NOT NULL,
    bug_id INT NOT NULL,
    FOREIGN KEY (release_id) REFERENCES releases(id) ON DELETE CASCADE,
    FOREIGN KEY (bug_id) REFERENCES bugs(id) ON DELETE CASCADE,
    UNIQUE (release_id, bug_id)
);

CREATE TABLE deployments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    release_id INT NOT NULL,
    environment ENUM('Staging','Production') DEFAULT 'Staging',
    deployed_by INT,
    verification_token VARCHAR(64) UNIQUE,
    verified BOOLEAN DEFAULT FALSE,
    verification_notes TEXT,
    deployed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (release_id) REFERENCES releases(id) ON DELETE CASCADE,
    FOREIGN KEY (deployed_by) REFERENCES users(id)
);

CREATE TABLE project_scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    project_id INT NOT NULL,
    filename VARCHAR(255),
    stored_name VARCHAR(255),
    files_scanned INT DEFAULT 0,
    findings_count INT DEFAULT 0,
    bugs_created INT DEFAULT 0,
    created_by INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    message VARCHAR(500) NOT NULL,
    link VARCHAR(500),
    is_read BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
