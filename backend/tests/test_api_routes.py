"""
Tests for API routes with focus on SQL injection prevention
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import User, Project, Task, db


class TestGetTasksApiSQLInjectionPrevention:
    """Test suite for SQL injection prevention in get_tasks_api endpoint"""

    def test_get_tasks_with_valid_search(self, client, sample_task):
        """Test that valid search queries work correctly"""
        response = client.get('/api/v1/tasks?search=Test')

        assert response.status_code == 200
        data = response.get_json()
        assert 'tasks' in data
        assert len(data['tasks']) >= 1
        # Verify the task title contains the search term
        assert any('Test' in task.get('title', '') for task in data['tasks'])

    def test_get_tasks_with_sql_injection_in_search(self, client, sample_task):
        """Test that SQL injection attempts in search parameter are blocked"""
        # Common SQL injection payloads
        sql_injection_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE tasks; --",
            "' UNION SELECT * FROM users --",
            "1' OR 1=1 --",
            "admin'--",
            "' OR 'a'='a",
            "1'; DELETE FROM tasks WHERE '1'='1",
        ]

        for payload in sql_injection_payloads:
            response = client.get(f'/api/v1/tasks?search={payload}')

            # Should return 200 but with no results or safe results
            assert response.status_code == 200
            data = response.get_json()
            assert 'tasks' in data

            # The payload should be treated as a literal search string, not SQL
            # So it should return empty results (no tasks with that literal string)
            # or safely handle it without executing malicious SQL
            tasks = data['tasks']

            # Verify database integrity - task should still exist
            with client.application.app_context():
                task_count = Task.query.count()
                assert task_count > 0, f"SQL injection may have deleted data with payload: {payload}"

    def test_get_tasks_with_sql_injection_in_assigned_to(self, client, sample_task, sample_user):
        """Test that SQL injection attempts in assigned_to parameter are blocked"""
        # This tests the specific vulnerability at line 224 (now fixed at line 227-228)
        sql_injection_payloads = [
            "1 OR 1=1",
            "1; DROP TABLE tasks; --",
            "1 UNION SELECT * FROM users",
            "1' OR '1'='1",
        ]

        for payload in sql_injection_payloads:
            response = client.get(f'/api/v1/tasks?search=Test&assigned_to={payload}')

            # Should return 200 with safe handling
            assert response.status_code == 200
            data = response.get_json()
            assert 'tasks' in data

            # Verify database integrity - check that no data was deleted
            with client.application.app_context():
                task_count = Task.query.count()
                user_count = User.query.count()
                assert task_count > 0, f"Tasks were deleted with payload: {payload}"
                assert user_count > 0, f"Users table was affected with payload: {payload}"

    def test_get_tasks_with_sql_injection_in_project_id(self, client, sample_task):
        """Test that SQL injection attempts in project_id parameter are blocked"""
        sql_injection_payloads = [
            "1 OR 1=1",
            "1; DROP TABLE projects; --",
            "1 UNION SELECT * FROM users",
        ]

        for payload in sql_injection_payloads:
            response = client.get(f'/api/v1/tasks?search=Test&project_id={payload}')

            assert response.status_code == 200
            data = response.get_json()
            assert 'tasks' in data

            # Verify database integrity
            with client.application.app_context():
                task_count = Task.query.count()
                project_count = Project.query.count()
                assert task_count > 0, f"Tasks were deleted with payload: {payload}"
                assert project_count > 0, f"Projects were deleted with payload: {payload}"

    def test_get_tasks_with_combined_sql_injection(self, client, sample_task, sample_user):
        """Test SQL injection with multiple parameters combined"""
        # Test the specific line 227-228 fix with combined attack
        response = client.get(
            "/api/v1/tasks?search='; DROP TABLE tasks; --&"
            "assigned_to=1 OR 1=1&"
            "project_id=1 UNION SELECT * FROM users"
        )

        assert response.status_code == 200
        data = response.get_json()
        assert 'tasks' in data

        # Verify all tables still exist and have data
        with client.application.app_context():
            task_count = Task.query.count()
            user_count = User.query.count()
            project_count = Project.query.count()
            assert task_count > 0, "Tasks table was compromised"
            assert user_count > 0, "Users table was compromised"
            assert project_count > 0, "Projects table was compromised"

    def test_get_tasks_with_valid_assigned_to(self, client, sample_task, sample_user, db_session):
        """Test that legitimate assigned_to queries work correctly"""
        # Assign the task to a user
        with client.application.app_context():
            task = Task.query.first()
            task.assigned_to = sample_user.id
            db_session.commit()

        response = client.get(f'/api/v1/tasks?search=Test&assigned_to={sample_user.id}')

        assert response.status_code == 200
        data = response.get_json()
        assert 'tasks' in data
        assert len(data['tasks']) >= 1
        # Verify the correct user assignment
        assert data['tasks'][0]['assigned_to'] == sample_user.id

    def test_get_tasks_with_valid_project_id(self, client, sample_task, sample_project):
        """Test that legitimate project_id queries work correctly"""
        response = client.get(f'/api/v1/tasks?search=Test&project_id={sample_project.id}')

        assert response.status_code == 200
        data = response.get_json()
        assert 'tasks' in data
        assert len(data['tasks']) >= 1
        # Verify the correct project assignment
        assert data['tasks'][0]['project_id'] == sample_project.id

    def test_get_tasks_without_search_param(self, client, sample_task):
        """Test that tasks can be retrieved without search parameter"""
        response = client.get('/api/v1/tasks')

        assert response.status_code == 200
        data = response.get_json()
        assert 'tasks' in data
        assert len(data['tasks']) >= 1

    def test_get_tasks_with_special_characters_in_search(self, client, sample_task, db_session):
        """Test that special characters in search are handled safely"""
        special_chars = [
            "%",
            "_",
            "\\",
            "'",
            '"',
            "%;--",
            "%' AND '1'='1",
        ]

        for char in special_chars:
            response = client.get(f'/api/v1/tasks?search={char}')

            assert response.status_code == 200
            data = response.get_json()
            assert 'tasks' in data

            # Verify database integrity
            with client.application.app_context():
                task_count = Task.query.count()
                assert task_count > 0, f"Database compromised with character: {char}"

    def test_get_tasks_with_empty_search(self, client, sample_task):
        """Test that empty search parameter is handled correctly"""
        response = client.get('/api/v1/tasks?search=')

        # When search is empty string, it should behave like no search parameter
        assert response.status_code == 200
        data = response.get_json()
        assert 'tasks' in data

    def test_get_tasks_with_unicode_in_search(self, client, sample_task):
        """Test that unicode characters in search don't cause issues"""
        unicode_strings = [
            "测试",  # Chinese
            "тест",  # Russian
            "🔍",   # Emoji
            "café",  # Accented characters
        ]

        for unicode_str in unicode_strings:
            response = client.get(f'/api/v1/tasks?search={unicode_str}')

            assert response.status_code == 200
            data = response.get_json()
            assert 'tasks' in data

    def test_get_tasks_preserves_functionality(self, client, db_session, sample_user, sample_project):
        """Test that the fix preserves original functionality"""
        # Create multiple tasks with different properties
        with client.application.app_context():
            task1 = Task(
                title='Frontend Development',
                description='Build the UI',
                project_id=sample_project.id,
                created_by=sample_user.id,
                assigned_to=sample_user.id,
                status='in_progress'
            )
            task2 = Task(
                title='Backend API',
                description='Create REST endpoints',
                project_id=sample_project.id,
                created_by=sample_user.id,
                status='pending'
            )
            db_session.add(task1)
            db_session.add(task2)
            db_session.commit()

        # Test search functionality
        response = client.get('/api/v1/tasks?search=Frontend')
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['tasks']) >= 1
        assert any('Frontend' in task['title'] for task in data['tasks'])

        # Test filtering by assigned_to
        response = client.get(f'/api/v1/tasks?search=Frontend&assigned_to={sample_user.id}')
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['tasks']) >= 1
        assert all(task['assigned_to'] == sample_user.id for task in data['tasks'])

        # Test filtering by project_id
        response = client.get(f'/api/v1/tasks?search=API&project_id={sample_project.id}')
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['tasks']) >= 1
        assert all(task['project_id'] == sample_project.id for task in data['tasks'])


class TestGetTasksApiEdgeCases:
    """Test edge cases and boundary conditions for get_tasks_api"""

    def test_get_tasks_with_nonexistent_assigned_to(self, client, sample_task):
        """Test querying with non-existent assigned_to ID"""
        response = client.get('/api/v1/tasks?search=Test&assigned_to=99999')

        assert response.status_code == 200
        data = response.get_json()
        assert 'tasks' in data
        # Should return empty or no matching tasks
        assert len(data['tasks']) == 0 or all(task['assigned_to'] != 99999 for task in data['tasks'])

    def test_get_tasks_with_nonexistent_project_id(self, client, sample_task):
        """Test querying with non-existent project_id"""
        response = client.get('/api/v1/tasks?search=Test&project_id=99999')

        assert response.status_code == 200
        data = response.get_json()
        assert 'tasks' in data
        assert len(data['tasks']) == 0 or all(task['project_id'] != 99999 for task in data['tasks'])

    def test_get_tasks_with_negative_ids(self, client, sample_task):
        """Test querying with negative ID values"""
        response = client.get('/api/v1/tasks?search=Test&assigned_to=-1&project_id=-1')

        assert response.status_code == 200
        data = response.get_json()
        assert 'tasks' in data

    def test_get_tasks_with_very_long_search_string(self, client, sample_task):
        """Test that very long search strings don't cause issues"""
        long_search = 'A' * 10000
        response = client.get(f'/api/v1/tasks?search={long_search}')

        assert response.status_code == 200
        data = response.get_json()
        assert 'tasks' in data
