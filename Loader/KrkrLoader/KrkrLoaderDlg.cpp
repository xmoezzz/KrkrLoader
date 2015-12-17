
// KrkrLoaderDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "KrkrLoader.h"
#include "KrkrLoaderDlg.h"
#include "afxdialogex.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


/***********************************************/

// CKrkrLoaderDlg 对话框

CKrkrLoaderDlg::CKrkrLoaderDlg(CWnd* pParent /*=NULL*/)
: CDialogEx(CKrkrLoaderDlg::IDD, pParent),
CheckChildProcess(FALSE),
TryHack(FALSE),
RunLE(FALSE)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CKrkrLoaderDlg::DoDataExchange(CDataExchange* pDX)
{
	DDX_Text(pDX, IDC_EDIT1, FilePath);
	DDV_MaxChars(pDX, FilePath, 2048);

	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CKrkrLoaderDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CKrkrLoaderDlg::OnBnClickedButton1)
	ON_EN_CHANGE(IDC_EDIT1, &CKrkrLoaderDlg::OnEnChangeEdit1)
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_CHECK1, &CKrkrLoaderDlg::OnBnClickedCheck1)
	ON_BN_CLICKED(IDC_CHECK2, &CKrkrLoaderDlg::OnBnClickedCheck2)
	ON_BN_CLICKED(IDOK, &CKrkrLoaderDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_CHECK3, &CKrkrLoaderDlg::OnBnClickedCheck3)
END_MESSAGE_MAP()


// CKrkrLoaderDlg 消息处理程序

BOOL CKrkrLoaderDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	ShowWindow(SW_SHOW);

	// TODO:  在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CKrkrLoaderDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CKrkrLoaderDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CKrkrLoaderDlg::OnBnClickedButton1()
{
	CString strFile = _T("");

	CFileDialog    dlgFile(TRUE, NULL, NULL, OFN_HIDEREADONLY, _T("Executable File (*.exe)|*.exe||"), NULL);

	if (dlgFile.DoModal())
	{
		strFile = dlgFile.GetPathName();
		FilePath = strFile;
		//UpdateData(TRUE);
	}
	UpdateData(FALSE);
}


void CKrkrLoaderDlg::OnEnChangeEdit1()
{
	GetDlgItemTextW(IDC_EDIT1, FilePath);
}


void CKrkrLoaderDlg::OnDropFiles(HDROP hDropInfo)
{
	HDROP hDrop = hDropInfo;
	UINT nFileNum = DragQueryFile(hDrop, 0xFFFFFFFF, NULL, 0);
	if (nFileNum == 1)
	{
		WCHAR strFileName[MAX_PATH] = { 0 };
		DragQueryFileW(hDrop, 0, strFileName, MAX_PATH);

		FilePath = strFileName;
		UpdateData(FALSE);
		BOOL See = FALSE;
		BOOL m_Ret = OnInit::IsExeFile(strFileName, See);
		if (See && m_Ret)
		{
			
			OnInit::WriteLog(FilePath, this->CheckChildProcess, this->TryHack, this->RunLE);
			BOOL ret = OnInit::Inject(FilePath);
			if (ret)
			{
				DragFinish(hDrop);
				PostQuitMessage(0);
			}
			else
			{
				DeleteFileW(L"KrkrLaunch.ini");
			}
		}
		else
		{
			MessageBoxW(L"Not an executable file", L"KrkrLaoder");
			FilePath = "";
			UpdateData(FALSE);
		}
	}
	else
	{
		MessageBoxW(L"Please Drop one file on this window", L"KrkrLaoder");
		DragFinish(hDrop);
		FilePath = "";
		UpdateData(FALSE);
	}
	CDialogEx::OnDropFiles(hDropInfo);
}

//Process
void CKrkrLoaderDlg::OnBnClickedCheck1()
{
	CheckChildProcess = !CheckChildProcess;
}

//Hack
void CKrkrLoaderDlg::OnBnClickedCheck2()
{
	TryHack = !TryHack;
}


//Launch
void CKrkrLoaderDlg::OnBnClickedOk()
{
	
	if (FilePath.GetLength() == 0)
	{
		MessageBox(L"Empty File Path", L"KrkrLoader");
		return;
	}
	if (!OnInit::CheckFile(FilePath))
	{
		MessageBox(L"Could not open selected file", L"KrkrLoader");
		return;
	}

	BOOL s = FALSE;
	BOOL ret = OnInit::IsExeFile(FilePath, s);
	if (ret && s)
	{
		if (OnInit::Inject(FilePath))
		{
			OnInit::WriteLog(FilePath, this->CheckChildProcess, this->TryHack, this->RunLE);
		}
		else
		{
			MessageBox(L"Failed to inject @_@", L"KrkrLoader");
		}
	}
	else
	{
		MessageBoxW(L"Not an executable file", L"KrkrLaoder");
	}

	CDialogEx::OnOK();
}

//X'moe LE
void CKrkrLoaderDlg::OnBnClickedCheck3()
{
	RunLE = !RunLE;
}
