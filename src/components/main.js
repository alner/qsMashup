let element = null;

export function main($element, layout) {
  var React = require('react');
  var App = require('./app');

  console.log('*** paint ***');
  console.log($element, layout);
  element = ($element)[0];
  React.render(<App layout={layout} />, element);
}

export function destroy() {
  if (element) {
    React.unmountComponentAtNode(element);
    element = null;
  }
}
