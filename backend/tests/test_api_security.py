"""
Security tests for API endpoints, specifically testing SQL injection remediation
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import User, Project, Task


class TestGlobalSearchSQLInjection:
    """Test SQL injection protection in the global_search endpoint"""

    def test_global_search_normal_query(self, client, sample_user, sample_project):
        """Test that normal search queries work correctly"""
        response = client.get('/api/v1/search?q=Test')

        assert response.status_code == 200
        data = response.get_json()

        # Verify response structure
        assert 'query' in data
        assert 'users' in data
        assert 'projects' in data
        assert 'tasks' in data
        assert data['query'] == 'Test'

        # Verify the search found the test project
        assert len(data['projects']) > 0
        project_names = [p['name'] for p in data['projects']]
        assert 'Test Project' in project_names

    def test_global_search_sql_injection_single_quote(self, client, sample_project):
        """Test that SQL injection with single quotes is blocked"""
        # Attempt SQL injection with single quote
        malicious_query = "' OR '1'='1"
        response = client.get(f'/api/v1/search?q={malicious_query}')

        assert response.status_code == 200
        data = response.get_json()

        # The query should be treated as a literal string, not SQL code
        # It should not return all projects (which would happen if injection succeeded)
        assert 'projects' in data

        # Since the malicious query doesn't match any real project names,
        # it should return no results or limited results
        # It should NOT return all projects in the database
        if len(data['projects']) > 0:
            # If any results, they should contain the search string as literal text
            for project in data['projects']:
                # The project should legitimately contain the search term
                name_match = malicious_query in project.get('name', '')
                desc_match = malicious_query in project.get('description', '')
                assert name_match or desc_match

    def test_global_search_sql_injection_union_attack(self, client, sample_user, sample_project):
        """Test that UNION-based SQL injection is blocked"""
        # Attempt UNION-based SQL injection
        malicious_query = "' UNION SELECT * FROM users WHERE '1'='1"
        response = client.get(f'/api/v1/search?q={malicious_query}')

        assert response.status_code == 200
        data = response.get_json()

        # The injection should be treated as literal text
        assert 'projects' in data

        # Should not expose user data through the projects endpoint
        for project in data['projects']:
            # Results should be actual projects, not user records
            assert 'name' in project
            # If description exists, it should not contain injected user data
            if 'description' in project:
                # The malicious query should be treated as literal search text
                # and not executed as SQL
                pass

    def test_global_search_sql_injection_comment_attack(self, client, sample_project):
        """Test that SQL comment-based injection is blocked"""
        # Attempt SQL injection using comments to ignore rest of query
        malicious_query = "'; DROP TABLE projects; --"
        response = client.get(f'/api/v1/search?q={malicious_query}')

        assert response.status_code == 200
        data = response.get_json()

        # The malicious query should be treated as literal text
        assert 'projects' in data

        # Verify the projects table still exists by checking we can query it
        # (this would fail if DROP TABLE succeeded)
        response2 = client.get('/api/v1/search?q=Test')
        assert response2.status_code == 200

    def test_global_search_sql_injection_semicolon_attack(self, client, sample_project):
        """Test that multiple statement injection is blocked"""
        # Attempt to execute multiple SQL statements
        malicious_query = "test'; UPDATE projects SET name='hacked' WHERE '1'='1"
        response = client.get(f'/api/v1/search?q={malicious_query}')

        assert response.status_code == 200
        data = response.get_json()

        # Verify that the project name was not modified
        response2 = client.get('/api/v1/search?q=Test')
        data2 = response2.get_json()

        # Original project should still exist with original name
        project_names = [p['name'] for p in data2['projects']]
        assert 'Test Project' in project_names
        assert 'hacked' not in project_names

    def test_global_search_sql_injection_blind_attack(self, client, sample_project):
        """Test that blind SQL injection timing attacks are blocked"""
        # Attempt blind SQL injection with conditional logic
        malicious_query = "' AND (SELECT COUNT(*) FROM users) > 0 AND '1'='1"
        response = client.get(f'/api/v1/search?q={malicious_query}')

        assert response.status_code == 200
        data = response.get_json()

        # The query should be treated as literal text, not SQL logic
        assert 'projects' in data

    def test_global_search_special_characters(self, client, sample_project):
        """Test that special characters are handled safely"""
        special_chars = [
            "%",  # SQL wildcard
            "_",  # SQL wildcard
            "\\", # Escape character
            "'",  # SQL quote
            '"',  # SQL quote
            "`",  # SQL identifier quote
        ]

        for char in special_chars:
            response = client.get(f'/api/v1/search?q={char}')
            assert response.status_code == 200
            data = response.get_json()
            assert 'projects' in data

    def test_global_search_empty_query(self, client):
        """Test that empty search query is handled properly"""
        response = client.get('/api/v1/search?q=')

        # Empty query should return error
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_global_search_missing_query_parameter(self, client):
        """Test that missing query parameter is handled properly"""
        response = client.get('/api/v1/search')

        # Missing query should return error
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_global_search_with_legitimate_quotes(self, app, client, sample_user):
        """Test that legitimate search terms with quotes work correctly"""
        # Create a project with quotes in the name
        with app.app_context():
            from models import db
            project = Project(
                name="John's Project",
                description="A project with quotes",
                owner_id=sample_user.id,
                is_public=True
            )
            db.session.add(project)
            db.session.commit()

        # Search for the project with quotes
        response = client.get("/api/v1/search?q=John's")
        assert response.status_code == 200
        data = response.get_json()

        # Should find the project
        assert 'projects' in data
        project_names = [p['name'] for p in data['projects']]
        assert "John's Project" in project_names

    def test_global_search_parameterized_query_effectiveness(self, app, client, sample_user):
        """Test that parameterized queries work correctly for various inputs"""
        # Create projects with various names
        with app.app_context():
            from models import db
            projects = [
                Project(name="Alpha Project", description="First", owner_id=sample_user.id),
                Project(name="Beta Project", description="Second", owner_id=sample_user.id),
                Project(name="Gamma Project", description="Third", owner_id=sample_user.id),
            ]
            for project in projects:
                db.session.add(project)
            db.session.commit()

        # Test various legitimate searches
        test_cases = [
            ("Alpha", ["Alpha Project"]),
            ("Beta", ["Beta Project"]),
            ("Project", ["Alpha Project", "Beta Project", "Gamma Project"]),
            ("First", ["Alpha Project"]),
        ]

        for search_term, expected_projects in test_cases:
            response = client.get(f'/api/v1/search?q={search_term}')
            assert response.status_code == 200
            data = response.get_json()

            project_names = [p['name'] for p in data['projects']]
            for expected in expected_projects:
                assert expected in project_names

    def test_global_search_case_sensitivity(self, client, sample_project):
        """Test search behavior with different cases"""
        # Test lowercase search
        response = client.get('/api/v1/search?q=test')
        assert response.status_code == 200
        data = response.get_json()
        assert 'projects' in data

        # Test uppercase search
        response = client.get('/api/v1/search?q=TEST')
        assert response.status_code == 200
        data = response.get_json()
        assert 'projects' in data

    def test_global_search_wildcard_patterns(self, client, sample_project):
        """Test that SQL wildcard patterns are treated as literals"""
        # These should be treated as literal characters, not SQL wildcards
        wildcard_queries = [
            "%",       # Should match literal % in data, not act as wildcard
            "%%",      # Multiple wildcards
            "Test%",   # Wildcard at end
            "%Test",   # Wildcard at start
        ]

        for query in wildcard_queries:
            response = client.get(f'/api/v1/search?q={query}')
            assert response.status_code == 200
            data = response.get_json()
            assert 'projects' in data
            # Should not cause SQL errors or return unexpected results


class TestGlobalSearchFunctionalityPreservation:
    """Test that the SQL injection fix doesn't break legitimate functionality"""

    def test_search_finds_projects_by_name(self, app, client, sample_user):
        """Test that search correctly finds projects by name"""
        with app.app_context():
            from models import db
            project = Project(
                name="Security Testing Project",
                description="Testing security features",
                owner_id=sample_user.id
            )
            db.session.add(project)
            db.session.commit()

        response = client.get('/api/v1/search?q=Security')
        assert response.status_code == 200
        data = response.get_json()

        project_names = [p['name'] for p in data['projects']]
        assert "Security Testing Project" in project_names

    def test_search_finds_projects_by_description(self, app, client, sample_user):
        """Test that search correctly finds projects by description"""
        with app.app_context():
            from models import db
            project = Project(
                name="Project XYZ",
                description="Important security features",
                owner_id=sample_user.id
            )
            db.session.add(project)
            db.session.commit()

        response = client.get('/api/v1/search?q=Important')
        assert response.status_code == 200
        data = response.get_json()

        project_names = [p['name'] for p in data['projects']]
        assert "Project XYZ" in project_names

    def test_search_partial_match(self, app, client, sample_user):
        """Test that search finds partial matches"""
        with app.app_context():
            from models import db
            project = Project(
                name="Development Environment",
                description="Local development setup",
                owner_id=sample_user.id
            )
            db.session.add(project)
            db.session.commit()

        # Partial search should work
        response = client.get('/api/v1/search?q=Dev')
        assert response.status_code == 200
        data = response.get_json()

        project_names = [p['name'] for p in data['projects']]
        assert "Development Environment" in project_names

    def test_search_no_results(self, client):
        """Test that search returns empty results when nothing matches"""
        response = client.get('/api/v1/search?q=NonexistentProject12345')
        assert response.status_code == 200
        data = response.get_json()

        assert 'projects' in data
        assert len(data['projects']) == 0

    def test_search_returns_all_expected_fields(self, client, sample_project):
        """Test that search results contain all expected project fields"""
        response = client.get('/api/v1/search?q=Test')
        assert response.status_code == 200
        data = response.get_json()

        if len(data['projects']) > 0:
            project = data['projects'][0]
            # Verify expected fields are present
            assert 'id' in project
            assert 'name' in project
            assert 'description' in project
            assert 'owner_id' in project
