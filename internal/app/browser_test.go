//go:build browser

package app

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mxschmitt/playwright-go"
	"golang.org/x/crypto/bcrypt"
)

func TestBrowserWorkflow(t *testing.T) {
	x := newTest(t)
	password := newID()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = x.a.S.DB.Exec("UPDATE users SET name='browser-admin',password=? WHERE id=?", string(hash), x.user); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(x.h)
	defer server.Close()
	x.a.C.PublicURL = server.URL
	pw, err := playwright.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Stop()
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{Headless: playwright.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()
	page, err := browser.NewPage(playwright.BrowserNewPageOptions{Viewport: &playwright.Size{Width: 1440, Height: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var pageErrors []string
	page.OnPageError(func(err error) { mu.Lock(); defer mu.Unlock(); pageErrors = append(pageErrors, err.Error()) })
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	expect := playwright.NewPlaywrightAssertions(10000)
	_, err = page.Goto(server.URL)
	check(err)
	check(page.Locator("#login-form input[name=name]").Fill("browser-admin"))
	check(page.Locator("#login-form input[name=password]").Fill(password))
	check(page.Locator("#login-form button[type=submit]").Click())
	check(expect.Locator(page.Locator("#shell")).ToBeVisible())
	check(page.Locator("#add-subnet").Click())
	check(page.Locator("#subnet-form input[name=name]").Fill("Datacenter · Production"))
	check(page.Locator("#subnet-form input[name=cidr]").Fill("192.0.2.0/24"))
	check(page.Locator("#subnet-form textarea").Fill("Primary application network"))
	check(page.Locator("#subnet-form button.primary").Click())
	check(expect.Locator(page.Locator("#subnet-title")).ToContainText("192.0.2.0/24"))
	check(expect.Locator(page.Locator(".ip-cell")).ToHaveCount(256))
	check(page.Locator(`button.ip-cell[aria-label^="192.0.2.10 "]`).Click())
	check(page.Locator("#address-form input[name=hostname]").Fill("app-01"))
	_, err = page.Locator("#address-form select[name=state]").SelectOption(playwright.SelectOptionValues{Values: &[]string{"static"}})
	check(err)
	check(page.Locator("#address-form button.primary").Click())
	check(expect.Locator(page.Locator(`button.ip-cell[aria-label^="192.0.2.10 "]`)).ToHaveClass("ip-cell state-static"))
	check(page.Locator(`button[data-page="imports"]`).Click())
	check(page.Locator("#import-data").Fill("name,cidr,site\nBranch,198.51.100.0/24,Branch"))
	check(page.Locator("#preview-import").Click())
	check(expect.Locator(page.Locator("#apply-import")).ToBeEnabled())
	page.OnDialog(func(d playwright.Dialog) { _ = d.Accept() })
	check(page.Locator("#apply-import").Click())
	check(expect.Locator(page.Locator("#import-result")).ToContainText(`"created": 1`))
	check(page.Locator(`button[data-page="networks"]`).Click())
	check(expect.Locator(page.Locator(".subnet-item")).ToHaveCount(2))
	dir := filepath.Join("..", "..", "dist", "verification")
	check(os.MkdirAll(dir, 0755))
	_, err = page.Screenshot(playwright.PageScreenshotOptions{Path: playwright.String(filepath.Join(dir, "subnet-desktop.png")), FullPage: playwright.Bool(true)})
	check(err)
	check(page.SetViewportSize(390, 844))
	_, err = page.Screenshot(playwright.PageScreenshotOptions{Path: playwright.String(filepath.Join(dir, "subnet-mobile.png")), FullPage: playwright.Bool(true)})
	check(err)
	overflow, err := page.Evaluate("document.documentElement.scrollWidth > window.innerWidth")
	check(err)
	if overflow == true {
		t.Error("mobile page overflows viewport")
	}
	check(page.Locator("#logout").Click())
	check(expect.Locator(page.Locator("#login")).ToBeVisible())
	mu.Lock()
	defer mu.Unlock()
	if len(pageErrors) > 0 {
		t.Fatal(pageErrors)
	}
}
