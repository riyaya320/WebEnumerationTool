import unittest
from unittest.mock import patch, mock_open, MagicMock
import requests
import tkinter as tk
from web_enumeration_tool import WebEnumerationTool 
class TestWebEnumerationTool(unittest.TestCase):

    def setUp(self):
        self.root = tk.Tk()
        self.app = WebEnumerationTool(self.root)
        self.app.file_path = 'test_directories.txt' 
    def test_read_directory_list(self):
        mock_file_data = 'dir1\n dir2\n dir3\n'
        with patch('builtins.open', mock_open(read_data=mock_file_data)) as mock_file:
            directories = self.app.read_directory_list('test_directories.txt')
            directories = [directory.strip() for directory in directories]  
            self.assertEqual(directories, ['dir1', 'dir2', 'dir3'])
            mock_file.assert_called_once_with('test_directories.txt', 'r')

    @patch('requests.get')
    def test_scan_directories(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)
        self.app.ip_address_entry = MagicMock(get=lambda: 'http://example.com')
        self.app.output_field = MagicMock()
        
        self.app.scan_directories('http://example.com', ['dir1', 'dir2'])
        
        self.assertTrue(self.app.output_field.insert.called)

    @patch('requests.get')
    @patch('nmap.PortScanner')
    def test_start_gather_info(self, mock_nmap, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'TestServer',
            'X-Powered-By': 'TestTech'
        }
        mock_response.text = '<html><head><title>Test</title></head><body></body></html>'
        
        mock_get.return_value = mock_response
        
        mock_nmap.return_value.scan.return_value = {
            "scan": {
                "testphp.vulnweb.com": {
                    "tcp": {
                        80: {'state': 'open'}
                    }
                }
            }
        }
        
        self.app.url_entry = MagicMock(get=lambda: 'http://example.com')
        self.app.output_field_info = MagicMock()
        
        self.app.start_gather_info()
        
        self.assertTrue(self.app.output_field_info.insert.called)

    @patch('tkinter.filedialog.askopenfilename', return_value='test_directories.txt')
    def test_browse_file(self, mock_askopenfilename):
        file_path = self.app.browse_file()
        self.assertEqual(file_path, 'test_directories.txt')
        mock_askopenfilename.assert_called_once()

    @patch('tkinter.filedialog.asksaveasfilename', return_value='test_output.txt')
    def test_save_output(self, mock_asksaveasfilename):
        self.app.output_field_info.get = MagicMock(return_value='test output')
        with patch('builtins.open', mock_open()) as mock_file:
            self.app.save_output()
            mock_file.assert_called_once_with('test_output.txt', 'w')
            mock_file().write.assert_called_once_with('test output')

    def tearDown(self):
        self.root.destroy()

if __name__ == '__main__':
    unittest.main()
