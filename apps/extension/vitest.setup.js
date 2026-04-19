import '@testing-library/jest-dom';

// Mock HTMLDialogElement methods that jsdom doesn't implement
if (typeof HTMLDialogElement !== 'undefined') {
  HTMLDialogElement.prototype.showModal =
    HTMLDialogElement.prototype.showModal ||
    function () {
      this.setAttribute('open', '');
    };
  HTMLDialogElement.prototype.close =
    HTMLDialogElement.prototype.close ||
    function () {
      this.removeAttribute('open');
      this.dispatchEvent(new Event('close'));
    };
}
