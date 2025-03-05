import { render, screen } from "@testing-library/react"
import Home from "@/app/page"

describe("Home", () => {
  it("renders the welcome message", () => {
    render(<Home />)
    const heading = screen.getByRole("heading", { name: /welcome to netsentry/i })
    expect(heading).toBeInTheDocument()
  })

  it("renders the login and signup buttons", () => {
    render(<Home />)
    const loginButton = screen.getByRole("link", { name: /login/i })
    const signupButton = screen.getByRole("link", { name: /sign up/i })
    expect(loginButton).toBeInTheDocument()
    expect(signupButton).toBeInTheDocument()
  })
})

