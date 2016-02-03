let element = null;

export function main($element, layout) {
  var React = require('react');
  var ReactDOM = require('react/lib/ReactDOM');
  var App = require('./app');

  console.log('*** paint ***');
  console.log($element, layout);
  element = ($element)[0];
  ReactDOM.render(<App layout={layout} />, element);
}

export function destroy() {
  if (element) {
    React.unmountComponentAtNode(element);
    element = null;
  }
}
