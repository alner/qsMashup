import React from 'react';
import Component from './base';
import Cell from './cell';

export default function main(element, layout) {
  console.log('*** paint ***');
  console.log(element, layout);
  React.render(<App />, element);
}

class App extends Component {
  render() {
    return (
      <div className="qv-object-markup">
        <Cell />
      </div>
    )
  }
}
