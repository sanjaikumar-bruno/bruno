import styled from 'styled-components';

const Wrapper = styled.div`
  table {
    width: 100%;
    border-collapse: collapse;
    font-weight: 600;
    table-layout: fixed;

    thead,
    td {
      border: 1px solid ${(props) => props.theme.table.border};
    }

    thead {
      color: ${(props) => props.theme.table.thead.color};
      font-size: 0.8125rem;
      user-select: none;
    }
    td {
      padding: 6px 10px;

      &:nth-child(1) {
        width: 30%;
      }

      &:nth-child(2) {
        width: 45%;
      }

      &:nth-child(3) {
        width: 25%;
      }

      &:nth-child(4) {
        width: 70px;
      }
    }
  }

  .btn-add-param {
    font-size: 0.8125rem;
  }

  input[type='text'] {
    width: 100%;
    border: solid 1px transparent;
    outline: none !important;
    color: ${(props) => props.theme.table.input.color};
    background: transparent;

    &:focus {
      outline: none !important;
      border: solid 1px transparent;
    }
  }

  input[type='radio'] {
    cursor: pointer;
    position: relative;
    top: 1px;
  }
`;

export default Wrapper;
