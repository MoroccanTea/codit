import { Component } from '@angular/core';

@Component({
  selector: 'app-temp-login',
  standalone: true,
  template: `<form (ngSubmit)="login()"></form>`,
})
export class TempLoginComponent {
  username = '';
  password = '';

  private readonly VALID_USERNAME = 'admin';
  private readonly VALID_PASSWORD = 'Qz7rT2025v'; // codit-expect: CWE-798 static credential compared at login

  login(): boolean {
    return this.username === this.VALID_USERNAME && this.password === this.VALID_PASSWORD;
  }

  showHint(): string {
    if (this.password.length >= 12) {
      return '';
    }
    // UI copy, not a secret
    const passwordValidationMessage = 'Password is too short'; // codit-safe: CWE-798 UI message, not a secret
    return passwordValidationMessage;
  }
}
