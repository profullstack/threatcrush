// react-blessed maps lowercase element names to blessed widget constructors.
// Declare them loosely so TS stops complaining about <box>, <list>, etc.

import 'react';

declare global {
  namespace JSX {
    interface IntrinsicElements {
      element: BlessedElement;
      box: BlessedElement;
      text: BlessedElement;
      line: BlessedElement;
      scrollablebox: BlessedElement;
      scrollabletext: BlessedElement;
      list: BlessedElement;
      form: BlessedElement;
      input: BlessedElement;
      textarea: BlessedElement;
      textbox: BlessedElement;
      button: BlessedElement;
      progressbar: BlessedElement;
      filemanager: BlessedElement;
      checkbox: BlessedElement;
      radioset: BlessedElement;
      radiobutton: BlessedElement;
      prompt: BlessedElement;
      question: BlessedElement;
      message: BlessedElement;
      loading: BlessedElement;
      listbar: BlessedElement;
      log: BlessedElement;
      table: BlessedElement;
      listtable: BlessedElement;
      terminal: BlessedElement;
      image: BlessedElement;
      video: BlessedElement;
      layout: BlessedElement;
    }
    type BlessedElement = Record<string, unknown> & { children?: unknown };
  }
}

// Ambient module declarations moved to ambient.d.ts so they work without
// the `import 'react'` above turning this file into a module.
